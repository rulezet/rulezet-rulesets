rule _20160921_262709d34b477380050375a3b5b2833b_20160921_3d83b7982fc5_996 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash3       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash4       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash5       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash6       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash7       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash8       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash9       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash10      = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash11      = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash12      = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1  = "on fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s2  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){re" ascii
    $s3  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"" ascii
    $s4  = "),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){" ascii
    $s5  = "\"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(func" ascii
    $s6  = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck()" ascii
    $s7  = "urn \"Ug\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s8  = "(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "function fuck(){return \"VMi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s10 = "k(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s11 = "ck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"To" ascii
    $s12 = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})()" ascii
    $s13 = " fuck(){return \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"" ascii
    $s14 = "k(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";}" ascii
    $s15 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s16 = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"To\";}" ascii
    $s17 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function" ascii
    $s18 = "XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s19 = "k\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Py\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}