rule _20160921_570295874daef65ccf11d909395ae377_20160921_68d4a1cff7c2_3800 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "0(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\"" ascii
    $s2 = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000" ascii
    $s3 = "n f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(function f000()" ascii
    $s5 = "GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s6 = "0(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}