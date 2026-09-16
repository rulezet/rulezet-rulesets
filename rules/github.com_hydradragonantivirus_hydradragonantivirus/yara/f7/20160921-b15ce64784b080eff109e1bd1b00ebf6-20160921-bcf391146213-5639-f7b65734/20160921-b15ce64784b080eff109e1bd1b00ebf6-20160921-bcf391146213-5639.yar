rule _20160921_b15ce64784b080eff109e1bd1b00ebf6_20160921_bcf391146213_5639 {
  meta:
    description = "datamaliciousorder - from files 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"" ascii
    $s2 = "Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s3 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function " ascii
    $s4 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})()," ascii
    $s5 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}