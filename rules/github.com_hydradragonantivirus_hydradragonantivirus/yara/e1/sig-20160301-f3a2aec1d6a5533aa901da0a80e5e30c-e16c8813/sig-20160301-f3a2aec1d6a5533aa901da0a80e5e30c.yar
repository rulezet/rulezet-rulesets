rule sig_20160301_f3a2aec1d6a5533aa901da0a80e5e30c {
  meta:
    description = "datamaliciousorder - file 20160301_f3a2aec1d6a5533aa901da0a80e5e30c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "463854246455be2271215e8acf246b5f4c704daab008ffa426e099fcc31a9a02"

  strings:
    $s1 = "subjectiveMuseum = saluteAgent[(\"s\\u0065p\\u0061\\u0072a\" + \"t\\u0069\\u006fn\", \"\\u006di\\u0067ra\" + \"t\\u0065\", funct" ascii
    $s2 = "subjectiveMuseum = saluteAgent[(\"s\\u0065p\\u0061\\u0072a\" + \"t\\u0069\\u006fn\", \"\\u006di\\u0067ra\" + \"t\\u0065\", funct" ascii
    $s3 = "while(phaseCompany[(\"a\\u006d\\u0070\\u0068\\u0069b\" + \"\\u0069\\u0061n\", \"\\u0072\\u0065\" + \"\\u0061dy\" + \"\\u0073\" +" ascii
    $s4 = "while(phaseCompany[(\"a\\u006d\\u0070\\u0068\\u0069b\" + \"\\u0069\\u0061n\", \"\\u0072\\u0065\" + \"\\u0061dy\" + \"\\u0073\" +" ascii
    $s5 = "collectGram = (((0 / 28) ^ (1 ^ 0)), this);" fullword ascii
    $s6 = "} catch(tractInfinitive) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}