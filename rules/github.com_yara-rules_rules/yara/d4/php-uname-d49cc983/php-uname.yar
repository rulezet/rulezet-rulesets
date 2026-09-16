rule php_uname {
    strings: 
        $ = "php_uname()"
    condition: 
        any of them and filesize < 500KB
}