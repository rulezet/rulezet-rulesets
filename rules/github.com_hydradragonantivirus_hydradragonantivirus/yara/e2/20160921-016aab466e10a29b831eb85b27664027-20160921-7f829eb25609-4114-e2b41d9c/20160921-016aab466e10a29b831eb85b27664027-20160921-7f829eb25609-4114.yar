rule _20160921_016aab466e10a29b831eb85b27664027_20160921_7f829eb25609_4114 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"W" ascii
    $s2 = "tion f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){r" ascii
    $s4 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000()" ascii
    $s5 = "){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}