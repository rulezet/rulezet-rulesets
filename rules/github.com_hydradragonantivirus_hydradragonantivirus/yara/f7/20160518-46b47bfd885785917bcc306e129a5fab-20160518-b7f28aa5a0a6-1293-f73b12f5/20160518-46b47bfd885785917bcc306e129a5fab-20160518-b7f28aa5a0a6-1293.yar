rule _20160518_46b47bfd885785917bcc306e129a5fab_20160518_b7f28aa5a0a6_1293 {
  meta:
    description = "datamaliciousorder - from files 20160518_46b47bfd885785917bcc306e129a5fab.js, 20160518_b7f28aa5a0a65bc1f3400a2fda4191db.js, 20160518_cd4d5013ad4f0469f442a6c389ad880a.js, 20160518_f22fa16f4655defeee7daa604d1a6121.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97058b521869a0ea91071e2bdaa27e28bffac2fa471ab9693028ccfa1c1ee390"
    hash2       = "43a0d10adc10fb1639541bf52cd934973783d9b2c1a6a2856aa495b61a38256a"
    hash3       = "f8bb3c9c29950ecef21cd00bc585ba71cc3a61754fbfc25e7f4c8e5acd7df31d"
    hash4       = "c3b1bae8ac365b979c0bc43a79d20c805bf90596bd0bc2f7573ce4d2aafc6449"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* t  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* t  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "dot1 /* t  */= true;/* t  */" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* t  */, A8name /* t  *" ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* t  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}