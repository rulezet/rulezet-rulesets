rule sig_20160301_f7a777b7e00ba5d29c82ce5dbc3f80b1 {
  meta:
    description = "datamaliciousorder - file 20160301_f7a777b7e00ba5d29c82ce5dbc3f80b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7579751abf0cf3b275e1da869f605eba12273f251ac5fbe0185848fbd1e070aa"

  strings:
    $s1 = "while(profileExtreme[(\"i\\u006ev\\u0065\" + \"st\", \"\\u0063\\u006fm\\u006d\\u0065\" + \"\\u006et\", \"\\u0063e\" + \"nt\\u007" ascii
    $s2 = "while(profileExtreme[(\"i\\u006ev\\u0065\" + \"st\", \"\\u0063\\u006fm\\u006d\\u0065\" + \"\\u006et\", \"\\u0063e\" + \"nt\\u007" ascii
    $s3 = "artilleryControl[(\"order\", \"a\\u006c\" + \"\\u0074\\u0065r\" + \"\\u006e\\u0061\\u0074\\u0069ve\", \"\\u0076\\u0061\\u0072i" ascii
    $s4 = "61m\" + \"or\\u0070\\u0068\" + \"ous\", \"\\u0077\\u0072i\\u0074e\")](profileExtreme[(\"\\u006d\\u0069\" + \"n\\u0075s\", functi" ascii
    $s5 = "modernCycle = (((0 ^ 1) * (0 ^ 1)), this);" fullword ascii
    $s6 = "} catch(sphericalPseudonym) {};" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    all of them
}