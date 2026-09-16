rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_178144255388_1448 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_d69f5159aadd1440760083d8952604c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash3       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"

  strings:
    $s1  = "tion f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2  = "unction f000(){return \"Vj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s3  = "n f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Y" ascii
    $s4  = "Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s5  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s6  = "(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";" ascii
    $s7  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return" ascii
    $s8  = "turn \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s9  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\"" ascii
    $s10 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\"" ascii
    $s11 = "(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";}" ascii
    $s12 = "turn \"HJm\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s13 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}