rule sig_20160301_3bef947480ff5845aa60c5cfa74adde7 {
  meta:
    description = "datamaliciousorder - file 20160301_3bef947480ff5845aa60c5cfa74adde7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50b8188355fc5c6c8c9a42bc081167f53adcb2171a170bdeef1bc33345c78009"

  strings:
    $s1 = "while(acousticCube[(\"\\u0069\\u0064e\" + \"\\u006etica\" + \"\\u006c\", \"\\u0072e\" + \"a\\u0064\" + \"ysta\\u0074e\")] < ((3 " ascii
    $s2 = "delegateDegradation = (((1) & (1 * 1)), this);" fullword ascii
    $s3 = "magazineBank = delegateDegradation[(\"\\u0063\\u0065\\u006eso\" + \"r\", \"h\\u0065\\u0072b\", \"\\u0074\\u0065\\u0072\\u006d\\u" ascii
    $s4 = "while(acousticCube[(\"\\u0069\\u0064e\" + \"\\u006etica\" + \"\\u006c\", \"\\u0072e\" + \"a\\u0064\" + \"ysta\\u0074e\")] < ((3 " ascii
    $s5 = "\"\\u0061\\u006d\", function String.prototype.banditTechnical() {" fullword ascii
    $s6 = "} catch(attackStart) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}