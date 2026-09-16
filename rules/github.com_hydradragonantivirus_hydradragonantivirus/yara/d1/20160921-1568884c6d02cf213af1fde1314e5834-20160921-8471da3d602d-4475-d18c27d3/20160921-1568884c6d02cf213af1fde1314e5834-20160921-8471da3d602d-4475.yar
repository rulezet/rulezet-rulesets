rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_8471da3d602d_4475 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = " \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s2 = "\"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s3 = "n \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(fu" ascii
    $s4 = "000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt" ascii
    $s5 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}