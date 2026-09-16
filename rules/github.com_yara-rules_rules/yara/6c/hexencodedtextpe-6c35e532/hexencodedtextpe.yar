rule HexEncodedTextPE
{
    meta:
        author = "Malware Utkonos"
        date = "2020-01-28"
        reference = "https://blog.reversinglabs.com/blog/rats-in-the-library"
        description = "Text string with hexadecimal encoded MZ/PE and comma+ separation"
    strings:
        $mz = /4D,.{0,6}5A/ nocase
        $pe = /50,.{0,6}45/
    condition:
        all of them
}