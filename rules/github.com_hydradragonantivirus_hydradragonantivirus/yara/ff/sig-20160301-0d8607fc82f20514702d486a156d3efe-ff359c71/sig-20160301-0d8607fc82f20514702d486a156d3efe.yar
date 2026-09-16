rule sig_20160301_0d8607fc82f20514702d486a156d3efe {
  meta:
    description = "datamaliciousorder - file 20160301_0d8607fc82f20514702d486a156d3efe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "522e7bb615ac0c4d77e99e8011a270060cafa167d9e7897d39f57666e735c4c6"

  strings:
    $s1 = "while (evolutionPlanet[(\"\\u0073\\u0061\\u006c\" + \"\\u006f\" + \"\\u006e\", \"\\u0061s\" + \"pe\\u0063\\u0074\", \"t\\u0061" ascii
    $s2 = "sumStrategy[(\"g\" + \"r\\u006f\" + \"up\", \"lea\\u0064e\" + \"r\", \"\\u0061cti\" + \"ve\", function String.prototype.citation" ascii
    $s3 = "while (evolutionPlanet[(\"\\u0073\\u0061\\u006c\" + \"\\u006f\" + \"\\u006e\", \"\\u0061s\" + \"pe\\u0063\\u0074\", \"t\\u0061" ascii
    $s4 = "centralAutonomous = ((2 * 2 * 11 / 11 * 2 * 2), this);" fullword ascii
    $s5 = "} catch (shuntEconomy) {};" fullword ascii

  condition:
    uint16(0) == 0x6563 and
    all of them
}