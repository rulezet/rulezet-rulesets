rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_1ccc6f9d608f_1445 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"

  strings:
    $s1  = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s2  = "i\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s3  = "unction f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s4  = "return \"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(" ascii
    $s5  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function " ascii
    $s6  = "return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})()" ascii
    $s7  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii
    $s8  = "0(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\"" ascii
    $s9  = "\"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(func" ascii
    $s10 = "),(function f000(){return \"Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s11 = "unction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii
    $s12 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s13 = "on f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}