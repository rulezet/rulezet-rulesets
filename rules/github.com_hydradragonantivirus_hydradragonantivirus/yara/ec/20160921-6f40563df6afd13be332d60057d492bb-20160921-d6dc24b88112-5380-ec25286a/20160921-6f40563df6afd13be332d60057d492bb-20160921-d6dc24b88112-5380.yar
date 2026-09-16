rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_d6dc24b88112_5380 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"
    hash3       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "ion f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s2 = "turn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(" ascii
    $s3 = "n \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(func" ascii
    $s4 = "h\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function" ascii
    $s5 = "ion f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}