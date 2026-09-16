rule _20160518_1371cc0a83a7d7821230eaf345b96106_20160518_bd24fd8f4d37_1277 {
  meta:
    description = "datamaliciousorder - from files 20160518_1371cc0a83a7d7821230eaf345b96106.js, 20160518_bd24fd8f4d37ada6776da04f32f0be87.js, 20160518_c9425a9dec74ea782bfcb0acb77585dd.js, 20160518_c99cf5f367fc3ba2199dd016f47b76f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cf538a4ab6993ba1ac166b45de8a414f5f2ba130658f6ba051d7f99c8d8fc4b"
    hash2       = "cd4b1ad2ac7438304a02da291a0e6397cab984ac59827d3872b27a6ed1464fc4"
    hash3       = "eafb3e6ee6fdfb1b050673159497ddf5f644ad0686fe700b20a1590a6e2cb5a2"
    hash4       = "c2825891320b1ea1f51d1431e33c997eddf912d5f8e49bf1038f2c489e8de667"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* j  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* j  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* j  */, A8name /* j  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* j  */;};" fullword ascii
    $s5 = "dot1 /* j  */= true;/* j  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}