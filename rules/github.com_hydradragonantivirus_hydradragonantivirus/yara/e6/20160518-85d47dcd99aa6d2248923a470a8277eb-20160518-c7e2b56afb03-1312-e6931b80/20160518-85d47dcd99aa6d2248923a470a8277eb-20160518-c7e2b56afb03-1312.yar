rule _20160518_85d47dcd99aa6d2248923a470a8277eb_20160518_c7e2b56afb03_1312 {
  meta:
    description = "datamaliciousorder - from files 20160518_85d47dcd99aa6d2248923a470a8277eb.js, 20160518_c7e2b56afb0323a402e7100cefd7c920.js, 20160518_da8befa724eac781b39979aec4136197.js, 20160519_3f39c434977c2eb6a9d8bdc79ba07c48.js, 20160519_e2c4ac3201d5ee296d94769302305f77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a142ef88d4458f0e6ee92b91c3785906ce65b01986a31e2d1b3dc407a697523"
    hash2       = "2db08a497cbf99b7d87dad1124c120a1dbef88c22d4bc83363cf579574c52df7"
    hash3       = "5b62accca61868e9767e86593f5a9111c11651c2dad2d7ba7601e036baef047d"
    hash4       = "fb41c31d2e784c7eec1c1eb279f8be8538587084163f6ed400f892fcca815730"
    hash5       = "72fd432d687aaa273e32c8b930d90a03ac186e2cb5b9aa6bb80fb1b6b1a4341b"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* M  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* M  */;};" fullword ascii
    $s3 = "newtonsCradle1 /* M  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "dot1 /* M  */= true;/* M  */" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* M  */, A8name /* M  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}