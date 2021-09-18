package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/davidbyttow/govips/v2/vips"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/h2non/filetype"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	log "github.com/sirupsen/logrus"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"
)

const TooLargeErrorMessage = "http: request body too large"
const JpegQuality = 85

var minioClient *minio.Client

var bucketName string
var signatureSecret string
var uploadSizeLimitBytes int64
var uploadResolutionLimitPixels int64
var port = os.Getenv("PORT")

func main() {
	initOptions()

	initLogger()

	initVips()
	defer vips.Shutdown()

	initMinioClient()

	r := createRouter()
	http.Handle("/", r)

	log.Infof("Listening on port %s", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Panicln(err)
	}
}

func initOptions() {
	bucketName = os.Getenv("MINIO_BUCKET_NAME")
	signatureSecret = os.Getenv("SIGNATURE_SECRET")
	uploadSizeLimitBytes = loadInteger("UPLOAD_LIMIT_MEGABYTES") * 1024 * 1024
	uploadResolutionLimitPixels = loadInteger("UPLOAD_LIMIT_MEGAPIXELS")*10 ^ 6
}

func loadInteger(key string) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		log.Panicf("Could not parse env variable %s: %s", key, err)
	}
	return value
}

func initVips() {
	vips.LoggingSettings(func(messageDomain string, messageLevel vips.LogLevel, message string) {
		msg := fmt.Sprintf("[%s] %v", messageDomain, message)

		switch messageLevel {
		case vips.LogLevelError:
		case vips.LogLevelCritical:
			log.Error(msg)
		case vips.LogLevelWarning:
			log.Warn(msg)
		case vips.LogLevelMessage:
		case vips.LogLevelInfo:
			log.Info(msg)
		case vips.LogLevelDebug:
			log.Debug(msg)
		}
	}, vips.LogLevelInfo)

	vips.Startup(nil)
}

func initLogger() {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		ForceColors:            os.Getenv("ENVIRONMENT") != "production",
		DisableLevelTruncation: true,
	})
}

func createRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/photo/{year:[0-9]{4}}/{month:[0-9]{2}}/{fileName}", uploadHandler)
	r.Use(loggingMiddleware)
	r.Use(signatureMiddleware)
	return r
}

func initMinioClient() {
	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	minioAccessKey := os.Getenv("MINIO_ACCESS_KEY")
	minioSecretKey := os.Getenv("MINIO_SECRET_KEY")

	var err error
	minioClient, err = minio.New(minioEndpoint, &minio.Options{
		Creds: credentials.NewStaticV4(minioAccessKey, minioSecretKey, ""),
	})

	if err != nil {
		log.Panicln(err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	// TODO: simplify output
	return handlers.CombinedLoggingHandler(log.StandardLogger().Writer(), next)
}

func signatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expiresString := r.URL.Query().Get("expires")
		signature := r.URL.Query().Get("signature")

		if expiresString == "" || signature == "" {
			http.Error(w, "Missing signature", http.StatusUnauthorized)
			return
		}

		now := time.Now().Unix()
		expires, err := strconv.ParseInt(expiresString, 10, 64)

		if err != nil || now > expires {
			http.Error(w, "Signature expired", http.StatusUnauthorized)
			return
		}

		h := hmac.New(sha256.New, []byte(signatureSecret))
		h.Write([]byte(expiresString))
		h.Write([]byte(r.URL.Path))
		sha := hex.EncodeToString(h.Sum(nil))

		if sha != signature {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	r.Body = http.MaxBytesReader(w, r.Body, uploadSizeLimitBytes)

	formFile, _, err := r.FormFile("file")
	if err != nil {
		if err.Error() == TooLargeErrorMessage {
			log.Errorf("Uploaded file is too large")
			http.Error(w, "", http.StatusRequestEntityTooLarge)
		} else {
			log.Errorf("Could not get file from body: %s", err)
			http.Error(w, "", http.StatusBadRequest)
		}
		return
	}

	defer formFile.Close()

	if !isSupportedFileType(formFile) {
		http.Error(w, "", http.StatusUnsupportedMediaType)
		return
	}

	img, err := vips.NewImageFromReader(formFile)
	if err != nil {
		log.Errorf("Could not read image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	resolution := img.Width() * img.Height()
	if int64(resolution) > uploadResolutionLimitPixels {
		log.Errorf("Uploaded file exceeds resolution limit: %d", resolution)
		http.Error(w, "", http.StatusRequestEntityTooLarge)
		return
	}

	if err := img.AutoRotate(); err != nil {
		log.Errorf("Could not rotate image: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Basically convert the color space to sRGB
	if err := img.OptimizeICCProfile(); err != nil {
		log.Errorf("Could not optimize ICC profile: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Remove metadata but keep the color profile
	if err := img.RemoveMetadata(); err != nil {
		log.Errorf("Could not remove metadata: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	ep := vips.NewJpegExportParams()
	ep.Quality = JpegQuality
	ep.OvershootDeringing = true
	// Disable progressive DCT, produces slightly larger file size but with faster encoding/decoding
	ep.Interlace = false
	compressedImageBytes, _, err := img.ExportJpeg(ep)

	reader := bytes.NewReader(compressedImageBytes)

	key := params["year"] + "/" + params["month"] + "/" + params["fileName"]

	// TODO: check if object already exists

	_, err = minioClient.PutObject(
		context.Background(),
		bucketName,
		key,
		reader,
		reader.Size(),
		minio.PutObjectOptions{
			ContentType: "image/jpeg",
		},
	)

	if err != nil {
		log.Errorf("Could not store image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func isSupportedFileType(file multipart.File) bool {
	head := make([]byte, 20)
	file.Read(head)
	file.Seek(0, io.SeekStart)

	kind, _ := filetype.Match(head)
	return kind.MIME.Value == "image/jpeg" || kind.MIME.Value == "image/png" || kind.MIME.Value == "image/heif"
}
