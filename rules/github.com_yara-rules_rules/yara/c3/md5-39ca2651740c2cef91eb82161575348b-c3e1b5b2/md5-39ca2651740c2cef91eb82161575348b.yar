rule md5_39ca2651740c2cef91eb82161575348b {
    strings: $ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/
    condition: any of them
}