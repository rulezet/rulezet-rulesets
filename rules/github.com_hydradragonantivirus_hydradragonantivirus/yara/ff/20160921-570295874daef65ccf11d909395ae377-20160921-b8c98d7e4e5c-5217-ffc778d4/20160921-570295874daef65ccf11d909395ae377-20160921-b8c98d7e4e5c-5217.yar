rule _20160921_570295874daef65ccf11d909395ae377_20160921_b8c98d7e4e5c_5217 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "Jm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s2 = "nction f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "ction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return" ascii
    $s4 = "000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ug" ascii
    $s5 = "(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}