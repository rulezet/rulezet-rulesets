rule sig_20160301_8dc9457f7a0f84bf94ddb51d9f1f287a {
  meta:
    description = "datamaliciousorder - file 20160301_8dc9457f7a0f84bf94ddb51d9f1f287a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0491f355dd864fb6d8aa24e8e92489f6cdbcc20e0c3ad20d04ee04537b5146f4"

  strings:
    $s1 = "divisionPause = (((1 * 1) ^ (212, 69, 144, 0)), this);" fullword ascii
    $s2 = "while(calendarAntenna[(\"\\u0073ym\\u0070h\" + \"\\u006f\\u006e\" + \"y\", \"\\u0061i\\u0072p\" + \"\\u006c\\u0061\\u006e\\u0065" ascii
    $s3 = "calendarAntenna[(\"\\u0072e\" + \"vi\\u0073\\u0069o\" + \"n\", \"\\u006dem\" + \"or\\u0069\" + \"\\u0061\\u006c\", \"\\u0070a\\u" ascii
    $s4 = "while(calendarAntenna[(\"\\u0073ym\\u0070h\" + \"\\u006f\\u006e\" + \"y\", \"\\u0061i\\u0072p\" + \"\\u006c\\u0061\\u006e\\u0065" ascii
    $s5 = "} catch(orientationMemoirs) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}