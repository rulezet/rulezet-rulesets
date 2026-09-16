rule sig_20160301_4e6b9a7022b72605f21216fbd88ef75d {
  meta:
    description = "datamaliciousorder - file 20160301_4e6b9a7022b72605f21216fbd88ef75d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bbf44002969dfb00733f278ee3470cc65be88467587bd4cbbd9f9cb51ba9448"

  strings:
    $s1 = "while (journalDelegate[(\"\\u006d\\u0065d\\u0061l\", \"\\u0062\\u006f\\u0078\", \"a\" + \"\\u006dphi\\u0062\" + \"i\" + \"\\u006" ascii
    $s2 = "while (journalDelegate[(\"\\u006d\\u0065d\\u0061l\", \"\\u0062\\u006f\\u0078\", \"a\" + \"\\u006dphi\\u0062\" + \"i\" + \"\\u006" ascii
    $s3 = "conceptionLocation = categoryComposer[(\"i\" + \"ma\\u0067\\u0065\", function String.prototype.momentumSanction() {" fullword ascii
    $s4 = "} catch (operatorSimulate) {};" fullword ascii
    $s5 = "categoryComposer = (1, this);" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    all of them
}