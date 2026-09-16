rule sig_20160301_04e07a4c1c7096be728fe9672f1ad697 {
  meta:
    description = "datamaliciousorder - file 20160301_04e07a4c1c7096be728fe9672f1ad697.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4caf1adf92e1735e0a742a964c8494d83fe78a78db231d61eb036abbfcd485d1"

  strings:
    $s1 = "while(formulaAssistant[(\"a\" + \"\\u006e\\u0065\\u0063d\" + \"\\u006fte\", \"se\\u0072\\u0069\" + \"o\\u0075s\", \"pi\" + \"\\u" ascii
    $s2 = "\\u0063\" + \"\\u0065\", function String.prototype.recordFact() {" fullword ascii
    $s3 = "while(formulaAssistant[(\"a\" + \"\\u006e\\u0065\\u0063d\" + \"\\u006fte\", \"se\\u0072\\u0069\" + \"o\\u0075s\", \"pi\" + \"\\u" ascii
    $s4 = "formulaAssistant[(\"\\u0063\" + \"\\u006f\\u006c\" + \"\\u006c\" + \"\\u0065\\u0063\\u0074\" + \"\\u006f\\u0072\", \"\\u0063\\u0" ascii
    $s5 = "colossalDog = ((1 & 1), this);" fullword ascii
    $s6 = "} catch(dollarContribution) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}