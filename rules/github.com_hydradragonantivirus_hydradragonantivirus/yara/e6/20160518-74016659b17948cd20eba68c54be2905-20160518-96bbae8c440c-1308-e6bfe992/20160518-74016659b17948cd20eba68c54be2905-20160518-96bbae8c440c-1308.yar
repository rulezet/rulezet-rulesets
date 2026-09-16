rule _20160518_74016659b17948cd20eba68c54be2905_20160518_96bbae8c440c_1308 {
  meta:
    description = "datamaliciousorder - from files 20160518_74016659b17948cd20eba68c54be2905.js, 20160518_96bbae8c440ccffa3c96e6f2f11b3376.js, 20160518_f940defdc1c2157e97458eb9e6e012f3.js, 20160519_49379eecbf69bc8ec27e8b3ca3600dd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5369f2b05b1ebcdf4db2ca10dc6fb3fcda0aed0fb367d5ed10a07976cf10e2f3"
    hash2       = "36de25235218c433fd4100e80a7fdd95c1c37815169c1eeb774a5891b345f1ae"
    hash3       = "6b9f3a78f87fdde52bcef4fdf0ac5be2bae724a7bca201f9931bffc9b17d4b83"
    hash4       = "350193b4a24aabdd6ae7c6dc7f94a0f1491b5836a53b9ae7a1c181954043f576"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* G  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* G  */, A8name /* G  *" ascii
    $s3 = "newtonsCradle1 /* G  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* G  */;};" fullword ascii
    $s5 = "dot1 /* G  */= true;/* G  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}