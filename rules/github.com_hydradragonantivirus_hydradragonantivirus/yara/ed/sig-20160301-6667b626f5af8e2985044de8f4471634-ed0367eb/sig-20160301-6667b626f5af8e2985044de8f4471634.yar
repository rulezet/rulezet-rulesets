rule sig_20160301_6667b626f5af8e2985044de8f4471634 {
  meta:
    description = "datamaliciousorder - file 20160301_6667b626f5af8e2985044de8f4471634.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef01937443838f25841b36832823609ea88560c2133913faf0209085c6bf3198"

  strings:
    $s1 = "while(transmissionEssay[(\"\\u0074\\u0072\\u0061nsp\" + \"la\\u006e\\u0074\", \"or\\u0069\\u0065\\u006e\" + \"t\\u0061t\" + \"i" ascii
    $s2 = "directivePrecedent = ((1 * 1), this);" fullword ascii
    $s3 = "while(transmissionEssay[(\"\\u0074\\u0072\\u0061nsp\" + \"la\\u006e\\u0074\", \"or\\u0069\\u0065\\u006e\" + \"t\\u0061t\" + \"i" ascii
    $s4 = "} catch(classTransit) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}