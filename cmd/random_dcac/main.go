package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rjchee/dcac_filemanager/dcac"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	uname, err := dcac.AddUname(dcac.ADDMOD)
	check(err)
	fm, err := uname.AddSub("fm", dcac.ADDMOD)
	check(err)
	users, err := fm.AddSub("users", dcac.ADDMOD)
	check(err)
	user, err := users.AddSub("admin", dcac.ADDMOD)
	check(err)
	userACL := user.ACL()
	regexpFile, err := os.Create("/tmp/regexps")
	check(err)
	defer regexpFile.Close()
	filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		isDir := fi.IsDir()
		if err != nil {
			if isDir {
				return filepath.SkipDir
			}
			return nil
		}
		if isDir {
			dcac.SetFileRdACL(path, userACL)
			return nil
		}
		quotedPath := regexp.QuoteMeta(path)
		if rand.Int()%2 == 0 {
			regexpFile.WriteString(fmt.Sprintf("allow %s\n", quotedPath))
			if err := dcac.SetFileRdACL(path, userACL); err != nil {
				fmt.Println(err)
			}
		} else {
			regexpFile.WriteString(fmt.Sprintf("disallow %s\n", quotedPath))
		}
		return nil
	})
}
