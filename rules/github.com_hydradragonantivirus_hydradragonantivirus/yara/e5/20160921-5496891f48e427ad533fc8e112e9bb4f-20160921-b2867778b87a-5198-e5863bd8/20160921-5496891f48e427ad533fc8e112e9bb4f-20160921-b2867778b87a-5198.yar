rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_b2867778b87a_5198 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = ";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s2 = "ZFe\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s3 = "n f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "ction f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s5 = "return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}