rule magecart_sotheby {
  meta:
    description = "sothebys magecart"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-12-04"

  strings:
    $s1 = "var _0xe80b=[" fullword ascii
    $s2 = "=document["
    $s3 = "if(typeof"
    $s4 = "=function(){if(window["
    $s5 = "var _0x14bf4e=document"
    $s6 = "while(--_0x3bfac4"
    $s7 = "hotlCkRyRv)"
    $s8 = "function LycqLBoqkw("
    $s9 = "unescape(encodeURIComponent"

  condition:
    (6 of them)
    or
    (all of them)
}