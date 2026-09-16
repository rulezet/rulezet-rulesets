rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_1b3a88384cf7_4474 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"

  strings:
    $s1 = "j\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s2 = "rn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s3 = " f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii
    $s4 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s5 = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}