rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_3ca43590701f_1843 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_3ca43590701fad2cb827b5edf3989d00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"

  strings:
    $s1  = "n f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s2  = "ion f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s3  = "00(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\"" ascii
    $s4  = "000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\"" ascii
    $s5  = "unction f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s6  = "unction f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s7  = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s8  = " f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj" ascii
    $s9  = "n f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s10 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}