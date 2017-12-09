package dcac

/*
#include "/home/raymond/dcac/user/include/dcac.h"
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
	"bytes"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ADDONLY = int(C.DCAC_ADDONLY)
	ADDMOD = int(C.DCAC_ADDMOD)
)

func toError(errno C.int) error {
	if errno == C.int(0) {
		return nil
	}
	return syscall.Errno(int(errno))
}

type ACL []string

func (a ACL) Add(name AttrName) ACL {
	addAttr := name.String()
	for _, attr := range a {
		if attr == addAttr {
			return a
		}
	}
	return append(a, addAttr)
}

func (a ACL) OrWith(o ACL) ACL {
	set := make(map[string]struct{})
	for _, attr := range a {
		set[attr] = struct{}{}
	}
	for _, attr := range o {
		if _, ok := set[attr]; !ok {
			a = append(a, attr)
		}
	}
	return a
}

func (a ACL) Remove(name AttrName) ACL {
	removeAttr := name.String()
	for i, attr := range a {
		if attr == removeAttr {
			return append(a[:i], a[i+1:]...)
		}
	}
	return a
}

func (a ACL) RemoveAll(o ACL) ACL {
	set := make(map[string]struct{})
	for _, attr := range o {
		set[attr] = struct{}{}
	}
	var ret ACL
	for _, attr := range a {
		if _, ok := set[attr]; !ok {
			ret = append(ret, attr)
		}
	}
	return ret
}

func (a ACL) AddAndRemoveAll(add, remove ACL) ACL {
	return a.RemoveAll(remove).OrWith(add)
}

func (a ACL) String() string {
	return strings.Join(a, "|")
}

func (a ACL) toC() *C.char {
	return C.CString(a.String())
}

func NewACL(attr string) ACL {
	return ACL([]string{attr})
}

type AttrName []string

func (a AttrName) ToC() *C.char {
	return C.CString(a.String())
}

func (a AttrName) String() string {
	return strings.Join(a, ".")
}

func (a AttrName) SubAttr(name string) AttrName {
	return append(a, name)
}

func (a AttrName) Parent() AttrName {
	return a[:len(a)-1]
}

func NewAttrName(s string) AttrName {
	return strings.Split(s, ".")
}

type Attr struct {
	Name AttrName
	fd int
}

func (a Attr) String() string {
	return a.Name.String()
}

func (a Attr) ACL() ACL {
	return NewACL(a.String())
}

func (a Attr) AddSub(name string, flag int) Attr {
	return Add(a.Name.SubAttr(name).String(), flag)
}

func (a Attr) Drop() error {
	return Drop(a)
}

func AddUname(flags int) Attr {
	fd := int(C.dcac_add_uname_attr(flags))
	for _, attr := range GetAttrList() {
		if attr.fd == fd {
			return attr
		}
	}
	return Attr{}
}

func AddGname(flags int) Attr {
	fd := int(C.dcac_add_gname_attr(flags))
	for _, attr := range GetAttrList() {
		if attr.fd == fd {
			return attr
		}
	}
	return Attr{}
}

func Add(attr string, flags int) Attr {
	cs := C.CString(attr)
	defer C.free(unsafe.Pointer(cs))
	fd := int(C.dcac_add_any_attr(cs, C.int(flags)))
	return Attr{attr, fd}
}

func Drop(attr Attr) error {
	return toError(C.close(attr.fd))
}

func SetDefRdACL(acl ACL) error {
	cs := acl.toC()
	defer C.free(unsafe.Pointer(cs))
	return toError(C.dcac_set_def_rdacl(cs))
}

func SetDefWrACL(acl ACL) error {
	cs := acl.toC()
	defer C.free(unsafe.Pointer(cs))
	return toError(C.dcac_set_def_wracl(cs))
}

func SetDefExACL(acl ACL) error {
	cs := acl.toC()
	defer C.free(unsafe.Pointer(cs))
	return toError(C.dcac_set_def_exacl(cs))
}

func SetDefMdACL(acl ACL) error {
	cs := acl.toC()
	defer C.free(unsafe.Pointer(cs))
	return toError(C.dcac_set_def_mdacl(cs))
}

func SetFileRdACL(file string, acl ACL) error {
	fileCS := C.CString(file)
	defer C.free(unsafe.Pointer(fileCS))
	aclCS := acl.toC()
	defer C.free(unsafe.Pointer(aclCS))
	return toError(C.dcac_set_file_rdacl(fileCS, aclCS))
}

func SetFileWrACL(file string, acl ACL) error {
	fileCS := C.CString(file)
	defer C.free(unsafe.Pointer(fileCS))
	aclCS := acl.toC()
	defer C.free(unsafe.Pointer(aclCS))
	return toError(C.dcac_set_file_wracl(fileCS, aclCS))
}

func SetFileExACL(file string, acl ACL) error {
	fileCS := C.CString(file)
	defer C.free(unsafe.Pointer(fileCS))
	aclCS := acl.toC()
	defer C.free(unsafe.Pointer(aclCS))
	return toError(C.dcac_set_file_exacl(fileCS, aclCS))
}

func SetFileMdACL(file string, acl ACL) error {
	fileCS := C.CString(file)
	defer C.free(unsafe.Pointer(fileCS))
	aclCS := acl.toC()
	defer C.free(unsafe.Pointer(aclCS))
	return toError(C.dcac_set_file_mdacl(fileCS, aclCS))
}

type FileACLs struct {
	Read ACL
	Write ACL
	Execute ACL
	Modify ACL
}

func GetFileACLs(file string) (*FileACLs, error) {
	dest := make([]byte, 1000)
	sz, err := syscall.Getxattr(file, "security.dcac.pm", dest)
	if err != nil {
		return err
	}
	dest = dest[:sz]
	acls := &FileACLs{}
	dest, acls.Read, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	dest, acls.Write, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	dest, acls.Execute, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	dest, acls.Modify, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	return acls, nil
}

func getFirstACL(xattr []byte) ([]byte, ACL, error) {
	remaining := int(xattr[0])
	remainingBytes := xattr[remaining:]
	xattr = xattr[2:remaining]
	beforeOps := int(xAttr[0])
	xattr = xattr[:beforeOps]
	metadataSz := int(xattr[2])
	xattr = xattr[metadataSz:]

	xattrBuff := bytes.NewBuffer(xattr)
	var acl ACL
	for attr, err := xattrBuff.ReadString(byte(0)); err != nil && len(attr) > 0; {
		acl = append(acl, attr)
	}
	if err != nil {
		return nil, ACL{}, err
	}

	return remainingBytes, acl, nil
}

func ModifyFileACLs(file string, add, remove *FileACLs) error {
	a, err := GetFileACLs(file)
	if err != nil {
		return err
	}
	if add != nil && add.Read != nil || remove != nil && remove.Read != nil {
		if err := SetFileRdACL(file, a.Read.AddAndRemoveAll(add.Read, remove.Read)); err != nil {
			return err
		}
	}
	if add != nil && add.Write != nil || remove != nil && remove.Write != nil {
		if err := SetFileWrACL(file, a.Write.AddAndRemoveAll(add.Write, remove.Write)); err != nil {
			return err
		}
	}
	if add != nil && add.Execute != nil || remove != nil && remove.Execute != nil {
		if err := SetFileRdACL(file, a.Execute.AddAndRemoveAll(add.Execute, remove.Execute)); err != nil {
			return err
		}
	}
	if add != nil && add.Modify != nil || remove != nil && remove.Modify != nil {
		if err := SetFileMdACL(file, a.Modify.AddAndRemoveAll(add.Modify, remove.Modify)); err != nil {
			return err
		}
	}
	return nil
}

func SetAttrACL(attr Attr, gateway *File, add, mod ACL) error {
	addCS := add.toC()
	modCS := mod.toC()
	defer C.free(unsafe.Pointer(addCS))
	defer C.free(unsafe.Pointer(modCS))
	return toError(C.dcac_set_attr_acl(C.int(attr.fd), C.int(gateway.Fd()), addCS, modCS))
}

func lookupAttrName(fd int) (string, error) {
	var buff [256]C.char
	err := toError(C.dcac_get_attr_name(fd, &buff[0], 256))
	if err == nil {
		return C.GoString(&buff[0]), nil
	}
	return "", err
}

func GetAttrList() []Attr {
	var fd_buffer [256]C.int
	size := int(C.dcac_get_attr_fd_list(&fd_buffer[0], 256))
	if size < 0 {
		log.Panic("too many attributes added")
	}

	var attrs []Attr
	for i := 0; i < size; i++ {
		fd := int(fd_buffer[i])
		attrName := lookupAttrName(fd)
		attrs = append(attrs, Attr{attrName, fd})
	}

	return attrs
}

func PrintAttrs() {
	for attr := range GetAttrList() {
		println(attr.String())
	}
}

func SetPMask(mask int) {
	C.dcac_set_mask(C.ushort(mask))
}

func GetPMask() int {
	return int(C.dcac_get_mask())
}

func Lock() {
	C.dcac_lockdown()
}

func Unlock() {
	C.dcac_unlock()
}

func CreateGatewayFile(attr Attr, filename string, add, mod ACL) error {
	gatewayFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	gatewayFile.Chmod(0644)
	return SetAttrACL(attr, gatewayFile, add, mod)
}

func OpenGatewayFile(filename string) (Attr, error) {
	file, err := os.Openfile(filename, os.O_RDONLY | ADDMOD, 0644)
	if err != nil {
		return Attr{}, err
	}
	fd := int(file.Fd())
	name := lookupAttrName(fd)
	return Attr{name, fd}, nil
}
