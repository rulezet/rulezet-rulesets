rule _20160921_2fddda42e5911e6501568e734d430149_20160921_3bce2f31e98c_4835 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_3bce2f31e98c152d025886ed17309773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"

  strings:
    $s1 = "\"ZIi\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s2 = " f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s3 = "{return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = "urn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s5 = "function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}