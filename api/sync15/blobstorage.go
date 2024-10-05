package sync15

import (
	"io"

	"github.com/juruen/rmapi/config"
	"github.com/juruen/rmapi/log"
	"github.com/juruen/rmapi/model"
	"github.com/juruen/rmapi/transport"
)

type BlobStorage struct {
	http        *transport.HttpClientCtx
	concurrency int
}

func NewBlobStorage(http *transport.HttpClientCtx) *BlobStorage {
	return &BlobStorage{
		http: http,
	}
}

const ROOT_NAME = "root"

func (b *BlobStorage) GetReader(hash string) (io.ReadCloser, error) {
	blob, _, err := b.http.GetBlobStream(config.DownloadFile + hash)
	return blob, err
}

func (b *BlobStorage) UploadBlob(hash string, reader io.Reader, size int64, checksum uint32) error {
	return b.http.PutBlobStream(config.DownloadFile+hash, reader, size, checksum)
}

func (b *BlobStorage) WriteRootIndex(roothash string, gen int64) (int64, error) {
	log.Info.Println("writing root with gen: ", gen)
	return b.http.PutRootBlobStream(config.PutRootUrl, roothash, gen)
}
func (b *BlobStorage) GetRootIndex() (string, int64, error) {
	var res model.RootRequest
	err := b.http.Get(transport.UserBearer, config.RootUrl, nil, &res)
	if err != nil {
		return "", 0, err
	}

	log.Info.Println("got root hash:", res.Hash)
	log.Info.Println("got root gen:", res.Generation)
	return res.Hash, res.Generation, nil

}
