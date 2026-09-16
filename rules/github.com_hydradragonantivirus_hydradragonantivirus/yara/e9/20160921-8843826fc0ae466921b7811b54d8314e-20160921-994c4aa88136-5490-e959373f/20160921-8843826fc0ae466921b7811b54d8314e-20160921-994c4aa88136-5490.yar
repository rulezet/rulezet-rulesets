rule _20160921_8843826fc0ae466921b7811b54d8314e_20160921_994c4aa88136_5490 {
  meta:
    description = "datamaliciousorder - from files 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash5       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})" ascii
    $s2 = "return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = ";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f" ascii
    $s4 = "Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "ion f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}