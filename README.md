# go-ipset

[![GoDoc](https://godoc.org/github.com/gmccue/go-ipset?status.svg)](https://godoc.org/github.com/Z10N0110/go-ipset)

go-ipset provides basic bindings for the [ipset kernel utility](http://ipset.netfilter.org/).

## Installation

``` shell
go get github.com/Z10N0110/go-ipset
```

## Usage

The following are some basic usage examples for go-iptables. For more information, please [checkout the godoc](https://github.com/Z10N0110/go-ipset.git).

``` go
import "github.com/Z10N0110/ipset"

// Construct a new ipset instance
ipset, err := ipset.New()
if err != nil {
    // Your custom error handling here.
}

// Create a new set
err := ipset.Create("my_set", "hash:ip")
if err != nil {
    // Your custom error handling here.
}
```

### Adding an entry to an ipset

``` go
err := ipset.Add("my_set", "127.0.0.1")
if err != nil {
    // Your custom error handling here.
}
```

### Removing an entry from an ipset

``` go
err := ipset.Add("my_set", "127.0.0.1")
if err != nil {
    // Your custom error handling here.
}
```

### Refresh named set with new entries

``` go
err := ipset.Refresh("my_set", "127.0.0.2", "192.168.1.1")
if err != nil {
    // Your custom error handling here.
}
```

### List all sets names

``` go
names, err := ipset.ListSetNames()
if err != nil {
    // Your custom error handling here.
}
```

### Get all entries of a named set

``` go
entries, err := ipset.ListEntries("my_set")
if err != nil {
    // Your custom error handling here.
}
```

### Save your ipset to a file

``` go
err := ipset.Save("my_set", "/tmp/my_set.txt")
if err != nil {
    // Your custom error handling here.
}
```

### Restore your ipset from a file

```go
err := ipset.Restore("/tmp/my_set.txt")
if err != nil {
    // Your custom error handling here.
}
```
