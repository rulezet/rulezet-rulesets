rule sig_20160301_5f25b132bf63cc6af33fefa31926720a {
  meta:
    description = "datamaliciousorder - file 20160301_5f25b132bf63cc6af33fefa31926720a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5be1c875e7943a1319ac452dace4b868b3ed94a5763c889250342cfdddcd1fd3"

  strings:
    $s1 = "operatorFront = (((50 - 50) + (([+!+[]]))), this);" fullword ascii
    $s2 = "hospitalGround = operatorFront[(\"\\u0061\" + \"dm\\u0069n\\u0069\" + \"st\\u0072\" + \"\\u0061t\\u0069on\", function String.pro" ascii
    $s3 = "hospitalGround = operatorFront[(\"\\u0061\" + \"dm\\u0069n\\u0069\" + \"st\\u0072\" + \"\\u0061t\\u0069on\", function String.pro" ascii
    $s4 = "while (hospitalGround[(\"\\u0062a\\u006e\" + \"a\\u006ea\", \"\\u0061\\u0063\\u0074\", \"\\u0061\\u006cma\\u006e\" + \"\\u0061c" ascii
    $s5 = "while (hospitalGround[(\"\\u0062a\\u006e\" + \"a\\u006ea\", \"\\u0061\\u0063\\u0074\", \"\\u0061\\u006cma\\u006e\" + \"\\u0061c" ascii
    $s6 = "Situation() {" fullword ascii
    $s7 = "} catch (frontImitation) {};" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}