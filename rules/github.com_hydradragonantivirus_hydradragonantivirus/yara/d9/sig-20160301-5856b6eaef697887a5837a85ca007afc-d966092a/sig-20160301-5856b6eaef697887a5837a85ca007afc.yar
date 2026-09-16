rule sig_20160301_5856b6eaef697887a5837a85ca007afc {
  meta:
    description = "datamaliciousorder - file 20160301_5856b6eaef697887a5837a85ca007afc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79608682a05d920b05349ee510ea278682330593163ffbb899f85b826b09f881"

  strings:
    $s1 = "operatorInvalid = (((([!+[] + !+[]]) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]])), (95 & 122), (1)), this);" fullword ascii
    $s2 = "while (minusBoxing[(\"ph\\u0065\\u006e\\u006f\\u006d\" + \"\\u0065n\\u006f\" + \"\\u006e\", \"di\\u0073\\u0063r\" + \"et\\u0065" ascii
    $s3 = "imitationOperate[(\"re\\u0067\" + \"\\u0075l\" + \"a\\u0074\\u0065\", function String.prototype.registrationVolcano() {" fullword ascii
    $s4 = "while (minusBoxing[(\"ph\\u0065\\u006e\\u006f\\u006d\" + \"\\u0065n\\u006f\" + \"\\u006e\", \"di\\u0073\\u0063r\" + \"et\\u0065" ascii
    $s5 = "} catch (symmetricalBallast) {};" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}