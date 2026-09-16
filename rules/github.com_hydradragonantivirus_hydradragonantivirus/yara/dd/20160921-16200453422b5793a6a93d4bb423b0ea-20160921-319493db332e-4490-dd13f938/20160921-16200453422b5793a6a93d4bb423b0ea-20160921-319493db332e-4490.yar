rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_319493db332e_4490 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash4       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash5       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "n f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"W" ascii
    $s2 = "ction f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s3 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s4 = "urn \"BIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s5 = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}