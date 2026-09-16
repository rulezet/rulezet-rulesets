rule _20160921_016aab466e10a29b831eb85b27664027_20160921_13c992e435ed_1940 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_13c992e435ed245b1977cea0df2db815.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"

  strings:
    $s1 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s2 = "{return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = "eturn \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})()," ascii
    $s4 = "n f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii
    $s5 = "f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn" ascii
    $s6 = "00(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\"" ascii
    $s7 = "\"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s8 = "n \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s9 = "\"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}