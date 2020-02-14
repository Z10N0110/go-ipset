// Package ipset provides a basic wrapper to the ipset utility for IPTables.
// More information about ipset can be found at:
// http://ipset.netfilter.org/index.html
package ipset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
)

// IPSet represents a ipset cmd executor.
type IPSet struct {
	Path string
}

// New creates a new IPSet.
func New() (*IPSet, error) {
	binPath, err := exec.LookPath("ipset")
	if err != nil {
		return nil, err
	}

	return &IPSet{binPath}, nil
}

// Create creates a new ipset with a given name and type.
// For more on set types, please see:
// http://ipset.netfilter.org/ipset.man.html#lbAT.
// Additional options can be passed to the Create() command. These options must
// be passed in a sequential key, value order.
// For example, ipset.Create("test", "hash:ip", "timeout", "300") will add a
// new set with the timeout option set to a value of 300.
func (set *IPSet) Create(name string, typ string, options ...string) error {
	return set.run(append([]string{"create", name, typ}, options...)...)
}

// Add adds a new entry to the named set.
func (set *IPSet) Add(name string, entry string, options ...string) error {
	return set.run(append([]string{"add", name, entry}, options...)...)
}

// AddUnique adds a new entry to the named set, if it does not already exist.
func (set *IPSet) AddUnique(name, entry string, options ...string) error {
	return set.run(append([]string{"add", name, entry, "-exist"}, options...)...)
}

// Delete removes an entry from the named set.
func (set *IPSet) Delete(name string, entry string, options ...string) error {
	return set.run(append([]string{"del", name, entry}, options...)...)
}

// Test tests if an entry exists in the named set.
// The exit status is zero if the tested entry is in the set, and nonzero if
// it is missing from the set.
func (set *IPSet) Test(name string, entry string, options ...string) error {
	return set.run(append([]string{"test", name, entry}, options...)...)
}

// Destroy destroys a named set, or all sets.
func (set *IPSet) Destroy(name string) error {
	return set.run("destroy", name)
}

// Save saves the named set or all sets to the given file.
func (set *IPSet) Save(name string, filename string) error {
	return set.run("save", name, "-file", filename)
}

// Restore restores a saved set from the given file.
func (set *IPSet) Restore(filename string) error {
	return set.run("restore", "-file", filename)
}

// Flush removes all entries from a named set.
func (set *IPSet) Flush(name string) error {
	return set.run("flush", name)
}

// Rename changes a set name from one value to another.
func (set *IPSet) Rename(from string, to string) error {
	return set.run("rename", from, to)
}

// Swap swaps the content of two existing sets.
func (set *IPSet) Swap(from string, to string) error {
	return set.run("swap", from, to)
}

// SetEntry ...
type SetEntry struct {
	XMLName xml.Name `xml:"member"`
	Elem    string   `xml:"elem"`
}

// Set ...
type Set struct {
	XMLName  xml.Name `xml:"ipset"`
	Name     string   `xml:"name,attr"`
	Type     string   `xml:"type"`
	Revision string   `xml:"revision"`
	Header   struct {
		XMLName    xml.Name `xml:"header"`
		Family     string   `xml:"family"`
		HashSize   int64    `xml:"hashsize"`
		Maxelem    int64    `xml:"maxelem"`
		MemSize    int64    `xml:"memsize"`
		References int64    `xml:"references"`
		Numentries int64    `xml:"numentries"`
	} `xml:"header"`
	Members struct {
		XMLName xml.Name    `xml:"members"`
		Members []*SetEntry `xml:"member"`
	} `xml:"members"`
}

// Sets ...
type Sets struct {
	XMLName xml.Name `xml:"ipsets"`
	Sets    []*Set   `xml:"ipset"`
}

func (set *IPSet) listXML(suppressMembers bool, args ...string) (sets []*Set, err error) {
	var stdout bytes.Buffer
	args = append([]string{"list", "-o", "xml"}, args...)
	if suppressMembers {
		args = append(args, "-t")
	}
	if err := set.runWithOutput(args, &stdout); err != nil {
		return nil, err
	}

	s := new(Sets)
	if err = xml.Unmarshal(stdout.Bytes(), s); err != nil {
		return nil, err
	}

	return s.Sets, nil
}

// List shows the named set by unmarshal xml output.
func (set *IPSet) List(name string, suppressMembers bool) (*Set, error) {
	sets, err := set.listXML(suppressMembers, name)
	if err != nil {
		return nil, err
	}
	if len(sets) != 1 {
		return nil, errors.New("list named set return results not equal one")
	}
	return sets[0], nil
}

// ListEntries shows the entries of a named set.
func (set *IPSet) ListEntries(name string) (entries []string, err error) {
	s, err := set.List(name, false)
	if err != nil {
		return
	}
	for _, m := range s.Members.Members {
		entries = append(entries, m.Elem)
	}
	return
}

// ListSets returns a slice of each set.
func (set *IPSet) ListSets(suppressMembers bool) (sets []*Set, err error) {
	return set.listXML(suppressMembers)
}

// ListSetNames returns a slice containing the name of each set.
func (set *IPSet) ListSetNames() (names []string, err error) {
	sets, err := set.listXML(false, "-n")
	if err != nil {
		return
	}
	for _, s := range sets {
		names = append(names, s.Name)
	}
	return
}

// GetReferences returns the named set's References
func (set *IPSet) GetReferences(name string) (int64, error) {
	s, err := set.List(name, true)
	if err != nil {
		return 0, err
	}
	return s.Header.References, nil
}

// Refresh use swap command to overwrite the set with the specified entries.
func (set *IPSet) Refresh(name string, entries ...string) error {

	tempname := name + "-swptemp"
	var err error

	s, err := set.List(name, true)
	if err != nil {
		return err
	}

	opts := []string{
		"family", s.Header.Family,
		"hashsize", strconv.FormatInt(s.Header.HashSize, 10),
		"maxelem", strconv.FormatInt(s.Header.Maxelem, 10),
	}
	if err = set.Create(tempname, s.Type, opts...); err != nil {
		msg := fmt.Sprintf("cannot create the temp set for swap: %s", err.Error())
		return errors.New(msg)
	}

	for _, entry := range entries {
		if err = set.AddUnique(tempname, entry); err != nil {
			return err
		}
	}

	if err = set.Swap(tempname, name); err != nil {
		return err
	}

	if err = set.Destroy(tempname); err != nil {
		return err
	}

	return nil
}

func (set *IPSet) run(args ...string) error {
	return set.runWithOutput(args, nil)
}

func (set *IPSet) runWithOutput(args []string, stdout io.Writer) error {
	args = append([]string{set.Path}, args...)

	var stderr bytes.Buffer
	cmd := exec.Cmd{
		Path:   set.Path,
		Args:   args,
		Stdout: stdout,
		Stderr: &stderr,
	}

	if err := cmd.Run(); err != nil {
		return errors.New(stderr.String())
	}

	return nil
}
