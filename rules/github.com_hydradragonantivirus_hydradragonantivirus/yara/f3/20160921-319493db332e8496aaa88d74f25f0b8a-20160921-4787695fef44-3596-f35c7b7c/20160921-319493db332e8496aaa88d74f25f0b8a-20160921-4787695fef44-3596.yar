rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_4787695fef44_3596 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash4       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "c\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s2 = "eturn \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f0" ascii
    $s4 = "ion f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "on f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s6 = "tion f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}