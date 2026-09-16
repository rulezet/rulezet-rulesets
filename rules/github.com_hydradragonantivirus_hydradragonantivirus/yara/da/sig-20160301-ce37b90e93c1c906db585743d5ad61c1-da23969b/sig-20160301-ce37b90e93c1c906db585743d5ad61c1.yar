rule sig_20160301_ce37b90e93c1c906db585743d5ad61c1 {
  meta:
    description = "datamaliciousorder - file 20160301_ce37b90e93c1c906db585743d5ad61c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93864cc0b2a7883ee0034fdef18947de843ea45345ad2221d73616bd9d164238"

  strings:
    $s1 = "while(statueCareer[(\"\\u0070o\\u0073\\u0069\\u0074i\" + \"v\\u0065\", \"is\\u006fla\" + \"te\", \"re\" + \"\\u0061dys\\u0074\" " ascii
    $s2 = "statueCareer = reanimationDistance[(\"\\u0073pon\" + \"\\u0073\" + \"o\" + \"r\", \"o\\u0063e\\u0061n\", \"\\u0061\\u006dmun\" +" ascii
    $s3 = "reanimationDistance = ((1 & 1), this);" fullword ascii
    $s4 = "while(statueCareer[(\"\\u0070o\\u0073\\u0069\\u0074i\" + \"v\\u0065\", \"is\\u006fla\" + \"te\", \"re\" + \"\\u0061dys\\u0074\" " ascii
    $s5 = "} catch(roleGram) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}