rule sig_20160303_0104b4e7caff9768bdd7e8853e77afb4 {
  meta:
    description = "datamaliciousorder - file 20160303_0104b4e7caff9768bdd7e8853e77afb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa07ea878c922523c2ebfb9cc089bb6eb4c2333a5c9518acf5df3c6c5e718c8"

  strings:
    $s1 = "rankLocation = intellectNumeral[brilliantPublication + portSituation + accuracyBinary](centLord + materialSpecification + barrel" ascii
    $s2 = "industryRevue = (((0 + 0) | (196 + 94)), (((12 | 28) - (96 - 70)), this));" fullword ascii
    $s3 = "while (degenerationAnarchy[importImpression + rhombusBroker + individualVacuum] < ((([!+[] + !+[]]) * (((([+!+[]])) + \"\" + (([" ascii
    $s4 = "while (degenerationAnarchy[importImpression + rhombusBroker + individualVacuum] < ((([!+[] + !+[]]) * (((([+!+[]])) + \"\" + (([" ascii
    $s5 = "Sanction + recordBarbarian);" fullword ascii
    $s6 = "minuteEmission = (function String.prototype.prizeHierarchy() {" fullword ascii
    $s7 = "} catch (gameArena) {};" fullword ascii

  condition:
    uint16(0) == 0x6961 and
    all of them
}