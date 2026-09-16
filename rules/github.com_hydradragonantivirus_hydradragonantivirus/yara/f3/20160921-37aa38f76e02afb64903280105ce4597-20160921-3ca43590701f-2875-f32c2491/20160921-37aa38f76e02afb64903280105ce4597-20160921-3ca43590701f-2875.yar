rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_3ca43590701f_2875 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_3ca43590701fad2cb827b5edf3989d00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"

  strings:
    $s1 = "return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})()" ascii
    $s2 = "n f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s3 = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"V" ascii
    $s4 = "tion f000(){return \"IAa\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\"" ascii
    $s6 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oh\";})(),(function f00" ascii
    $s7 = "{return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}