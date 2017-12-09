package dcac

/*
#include "/home/raymond/dcac/user/include/dcac.h"
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
	"bytes"
	"errors"
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
	newACL := make([]string, len(a))
	copy(newACL, a)
	return append(newACL, addAttr)
}

func (a ACL) OrWith(o ACL) ACL {
	set := make(map[string]struct{})
	for _, attr := range a {
		set[attr] = struct{}{}
	}
	newACL := make([]string, len(a))
	copy(newACL, a)
	for _, attr := range o {
		if _, ok := set[attr]; !ok {
			newACL = append(newACL, attr)
		}
	}
	return newACL
}

func (a ACL) Remove(name AttrName) ACL {
	removeAttr := name.String()
	var newACL ACL
	for _, attr := range a {
		if attr != removeAttr {
			newACL = append(newACL, attr)
		}
	}
	return newACL
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
	newAttrName := make([]string, len(a))
	copy(newAttrName, a)
	return append(newAttrName, name)
}

func (a AttrName) Parent() AttrName {
	newAttrName := make([]string, len(a))
	copy(newAttrName, a)
	return newAttrName[:len(a)-1]
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
	return Add(a.Name.SubAttr(name), flag)
}

func (a Attr) Drop() error {
	return Drop(a)
}

func findAddedAttr(fd int) (Attr, error) {
	attrs, err := GetAttrList()
	if err != nil {
		return Attr{}, err
	}
	for _, attr := range attrs {
		if attr.fd == fd {
			return attr, nil
		}
	}
	return Attr{}, errors.New("could not find added attribute")
}

func AddUname(flags int) (Attr, error) {
	fd := int(C.dcac_add_uname_attr(C.int(flags)))
	return findAddedAttr(fd)
}

func AddGname(flags int) (Attr, error) {
	fd := int(C.dcac_add_gname_attr(C.int(flags)))
	return findAddedAttr(fd)
}

func Add(attr AttrName, flags int) Attr {
	cs := C.CString(attr.String())
	defer C.free(unsafe.Pointer(cs))
	fd := int(C.dcac_add_any_attr(cs, C.int(flags)))
	return Attr{attr, fd}
}

func Drop(attr Attr) error {
	return toError(C.close(C.int(attr.fd)))
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
	isGateway := false
	if err != nil {
		sz, err = syscall.Getxattr(file, "security.dcac.at", dest)
		if err != nil {
			return nil, errors.New("no DCAC ACL found for file " + file)
		}
		isGateway = true
		dest = dest[2+remaining:]
	}
	dest = dest[:sz]
	acls := &FileACLs{}
	dest, acls.Read, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	if !isGateway {
		dest, acls.Write, err = getFirstACL(dest)
		if err != nil {
			return nil, err
		}
		dest, acls.Execute, err = getFirstACL(dest)
		if err != nil {
			return nil, err
		}
	}
	dest, acls.Modify, err = getFirstACL(dest)
	if err != nil {
		return nil, err
	}
	return acls, nil
}

func getFirstACL(xattr []byte) ([]byte, ACL, error) {
	remaining := int(xattr[0])+2
	remainingBytes := xattr[remaining:]
	xattr = xattr[2:remaining]
	beforeOps := int(xattr[0])+2
	xattr = xattr[:beforeOps]
	metadataSz := int(xattr[2])
	xattr = xattr[metadataSz:]

	xattrBuff := bytes.NewBuffer(xattr)
	var acl ACL
	for attr, err := xattrBuff.ReadString(byte(0)); err != nil || len(attr) > 0; {
		if err != nil {
			return nil, ACL{}, err
		}
		acl = append(acl, attr)
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

func SetAttrACL(attr Attr, gateway *os.File, add, mod ACL) error {
	addCS := add.toC()
	modCS := mod.toC()
	defer C.free(unsafe.Pointer(addCS))
	defer C.free(unsafe.Pointer(modCS))
	return toError(C.dcac_set_attr_acl(C.int(attr.fd), C.int(gateway.Fd()), addCS, modCS))
}

func lookupAttrName(fd int) (AttrName, error) {
	var buff [256]C.char
	err := toError(C.dcac_get_attr_name(C.int(fd), &buff[0], C.int(256)))
	if err == nil {
		return NewAttrName(C.GoString(&buff[0])), nil
	}
	return nil, err
}

func GetAttrList() ([]Attr, error) {
	var fd_buffer [256]C.int
	size := int(C.dcac_get_attr_fd_list(&fd_buffer[0], C.int(256)))
	if size < 0 {
		log.Panic("too many attributes added")
	}

	var attrs []Attr
	for i := 0; i < size; i++ {
		fd := int(fd_buffer[i])
		attrName, err := lookupAttrName(fd)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, Attr{attrName, fd})
	}

	return attrs, nil
}

func PrintAttrs() {
	attrs, err := GetAttrList()
	if err != nil {
		log.Println(err)
		return
	}
	for _, attr := range attrs {
		log.Println(attr.String())
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
	file, err := os.OpenFile(filename, os.O_RDONLY | ADDMOD, 0644)
	if err != nil {
		return Attr{}, err
	}
	fd := int(file.Fd())
	if name, err := lookupAttrName(fd); err != nil {
		return Attr{}, nil
	} else {
		return Attr{name, fd}, nil
	}
}
