rule php_malfunctions {
    strings:
        $ = "eval("
        $ = "gzinflate("
        $ = "str_rot13("
        $ = "base64_decode("
    condition: 
        3 of them and filesize < 500KB
}