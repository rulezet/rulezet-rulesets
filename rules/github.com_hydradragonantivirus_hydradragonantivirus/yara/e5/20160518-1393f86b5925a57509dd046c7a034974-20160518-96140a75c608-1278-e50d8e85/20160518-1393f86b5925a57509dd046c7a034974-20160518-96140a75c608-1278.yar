rule _20160518_1393f86b5925a57509dd046c7a034974_20160518_96140a75c608_1278 {
  meta:
    description = "datamaliciousorder - from files 20160518_1393f86b5925a57509dd046c7a034974.js, 20160518_96140a75c60895584a041f703c7bcfc6.js, 20160518_e4bbb4276f097ea0788252508eff396d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84e7c144de8802ecfacbca4d0c9cbed2f45fca53b189aed11654d763cf39f71a"
    hash2       = "7ad58c33c6f88d58f4b2b0cd28ab59b2292bab1831f9c530347354431bf8c8b2"
    hash3       = "05ae3922eada3dc286c718d2cd662cc66e26131c01cfc5246bdd58f316bcb3ef"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* f  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* f  */, A8name /* f  *" ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* f  */;};" fullword ascii
    $s4 = "dot1 /* f  */= true;/* f  */" fullword ascii
    $s5 = "newtonsCradle1 /* f  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}