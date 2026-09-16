rule sig_20160301_edc47f5ac41602763536a6bc123e529f {
  meta:
    description = "datamaliciousorder - file 20160301_edc47f5ac41602763536a6bc123e529f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "663b0a0191d3e315f08ee07b52898f62d2e9b16ff43ed4c69cf56af06252d336"

  strings:
    $s1 = "while(rationalGuide[(\"\\u0063\" + \"\\u0079l\\u0069\\u006e\\u0064\\u0065\" + \"\\u0072\", \"\\u0072ea\" + \"d\" + \"yst\\u0061t" ascii
    $s2 = "attractionUnison = ((1 + 0), this);" fullword ascii
    $s3 = "while(rationalGuide[(\"\\u0063\" + \"\\u0079l\\u0069\\u006e\\u0064\\u0065\" + \"\\u0072\", \"\\u0072ea\" + \"d\" + \"yst\\u0061t" ascii
    $s4 = "conductorCaste = attractionUnison[(\"\\u0070\\u0072a\\u0063\" + \"\\u0074i\\u0063\\u0061\" + \"\\u006c\", function String.protot" ascii
    $s5 = "conductorCaste = attractionUnison[(\"\\u0070\\u0072a\\u0063\" + \"\\u0074i\\u0063\\u0061\" + \"\\u006c\", function String.protot" ascii
    $s6 = "} catch(rhombusSpiral) {};" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    all of them
}