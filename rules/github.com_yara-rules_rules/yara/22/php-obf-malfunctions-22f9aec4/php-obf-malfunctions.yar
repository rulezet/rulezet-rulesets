rule php_obf_malfunctions {
    strings:
        $ = "eval(base64_decode"
        $ = "eval(gzinflate"
        $ = "str_rot13(base64_decode"
    condition: 
        any of them and filesize < 500KB
}