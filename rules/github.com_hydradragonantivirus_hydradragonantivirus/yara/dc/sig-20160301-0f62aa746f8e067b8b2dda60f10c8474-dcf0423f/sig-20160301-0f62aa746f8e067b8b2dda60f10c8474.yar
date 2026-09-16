rule sig_20160301_0f62aa746f8e067b8b2dda60f10c8474 {
  meta:
    description = "datamaliciousorder - file 20160301_0f62aa746f8e067b8b2dda60f10c8474.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc4e912db37cea2adc41907155e3a24686ddf26df01ba02161ebc6795b1bd471"

  strings:
    $s1 = "dynamicBanana[(\"c\\u0061\" + \"\\u006c\" + \"\\u0065\\u006e\" + \"\\u0064\\u0061r\", function String.prototype.versionHall() {" fullword ascii
    $s2 = "while (modalMemoirs[(\"mo\\u0064\" + \"\\u0061l\", \"e\\u0073\\u0073a\\u0079\", \"re\\u0061\\u0064\" + \"y\\u0073t\\u0061\\u0074" ascii
    $s3 = "while (modalMemoirs[(\"mo\\u0064\" + \"\\u0061l\", \"e\\u0073\\u0073a\\u0079\", \"re\\u0061\\u0064\" + \"y\\u0073t\\u0061\\u0074" ascii
    $s4 = "symmetricalBall = (((41 - 25) / (16 | 0)), this);" fullword ascii
    $s5 = "} catch (presumptionMedical) {};" fullword ascii

  condition:
    uint16(0) == 0x7973 and
    all of them
}