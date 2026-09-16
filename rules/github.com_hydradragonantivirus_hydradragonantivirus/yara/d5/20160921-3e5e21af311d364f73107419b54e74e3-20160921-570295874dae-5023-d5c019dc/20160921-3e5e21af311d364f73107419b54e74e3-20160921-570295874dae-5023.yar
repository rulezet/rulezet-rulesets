rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_570295874dae_5023 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash4       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\"" ascii
    $s3 = "00(){return \"MKa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\"" ascii
    $s4 = "000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa" ascii
    $s5 = "unction f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}