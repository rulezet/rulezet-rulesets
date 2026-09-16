rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_a1cbb43a1e22_2961 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f00" ascii
    $s2 = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s3 = "on f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s4 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(fun" ascii
    $s5 = "turn \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})()" ascii
    $s6 = "00(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu" ascii
    $s7 = "(function f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}