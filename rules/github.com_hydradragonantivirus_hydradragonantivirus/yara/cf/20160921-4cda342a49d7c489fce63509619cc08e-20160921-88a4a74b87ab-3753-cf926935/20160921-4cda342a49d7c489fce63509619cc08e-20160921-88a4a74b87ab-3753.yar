rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_3753 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash3       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash4       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash5       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash6       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s2 = "eturn \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s3 = "ion fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return" ascii
    $s4 = "ction fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s5 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s6 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}