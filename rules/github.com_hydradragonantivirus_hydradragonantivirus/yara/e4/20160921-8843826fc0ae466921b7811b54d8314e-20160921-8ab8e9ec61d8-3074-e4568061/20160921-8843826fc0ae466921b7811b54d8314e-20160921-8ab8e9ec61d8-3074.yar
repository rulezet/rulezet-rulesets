rule _20160921_8843826fc0ae466921b7811b54d8314e_20160921_8ab8e9ec61d8_3074 {
  meta:
    description = "datamaliciousorder - from files 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash2       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash3       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = "0(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "ion f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s3 = " \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s4 = "unction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){re" ascii
    $s5 = "(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(" ascii
    $s6 = "ion f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"" ascii
    $s7 = "),(function f000(){return \"Ot\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}