package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/davidbyttow/govips/v2/vips"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strconv"
	"time"
)

const TooLargeErrorMessage = "http: request body too large"
const UploadSizeLimitMegabytes = 15
const JpegQuality = 85

var minioClient *minio.Client
var bucketName = os.Getenv("MINIO_BUCKET_NAME")
var signatureSecret = os.Getenv("SIGNATURE_SECRET")
var port = os.Getenv("PORT")

func main() {
	vips.Startup(nil)
	defer vips.Shutdown()

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

	r := mux.NewRouter()
	r.HandleFunc("/photo/{year:[0-9]{4}}/{month:[0-9]{2}}/{fileName}", uploadHandler)
	r.Use(func(next http.Handler) http.Handler {
		// TODO: review format and user logger
		return handlers.CombinedLoggingHandler(os.Stdout, next)
	})
	r.Use(signatureMiddleware)

	http.Handle("/", r)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Panicln(err)
	}
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

	r.Body = http.MaxBytesReader(w, r.Body, UploadSizeLimitMegabytes*1024*1024)

	formFile, _, err := r.FormFile("file")
	if err != nil {
		if err.Error() == TooLargeErrorMessage {
			http.Error(w, "", http.StatusRequestEntityTooLarge)
		} else {
			log.Errorf("Could not get file from body: %s", err)
			http.Error(w, "", http.StatusBadRequest)
		}

		return
	}

	defer formFile.Close()

	img, err := vips.NewImageFromReader(formFile)
	if err != nil {
		log.Errorf("Could not read image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if err := img.AutoRotate(); err != nil {
		log.Errorf("Could not process image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Basically convert the color space to sRGB
	if err := img.OptimizeICCProfile(); err != nil {
		log.Errorf("Could not process image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Remove metadata but keep the color profile
	if err := img.RemoveMetadata(); err != nil {
		log.Errorf("Could not process image file: %s", err)
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
		minio.PutObjectOptions{},
	)

	if err != nil {
		log.Errorf("Could not store image file: %s", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
}
