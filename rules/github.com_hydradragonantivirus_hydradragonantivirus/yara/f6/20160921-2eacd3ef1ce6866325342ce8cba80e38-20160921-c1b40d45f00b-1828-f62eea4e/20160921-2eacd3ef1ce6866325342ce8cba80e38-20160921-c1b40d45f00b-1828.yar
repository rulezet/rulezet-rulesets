rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_c1b40d45f00b_1828 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash3       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"

  strings:
    $s1  = "000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk" ascii
    $s2  = "\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"OMd\";})(),(function " ascii
    $s3  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000()" ascii
    $s4  = "(function f000(){return \"Um\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s5  = "urn \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(" ascii
    $s6  = "n \"BMj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(fu" ascii
    $s7  = "MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s8  = " f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s9  = "\"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(fun" ascii
    $s10 = "(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}