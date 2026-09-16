rule fromCharCode_in_unicode {
    strings: 
        $ = "\\u0066\\u0072\\u006f\\u006d\\u0043\\u0068\\u0061\\u0072\\u0043\\u006f\\u0064\\u0065"
    condition: 
        any of them and filesize < 500KB
}