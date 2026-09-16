rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_9a54c73297e1_106 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash3       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1  = "ion f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s2  = "\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s3  = "unction f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){ret" ascii
    $s4  = "){return \"Vu\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"KXg\";})" ascii
    $s5  = "ion f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return" ascii
    $s6  = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s7  = "Iq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function" ascii
    $s8  = "function f000(){return \"Wh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s9  = "n f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"B" ascii
    $s10 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(" ascii
    $s11 = " f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Q" ascii
    $s12 = "0(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\"" ascii
    $s13 = "turn \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})()," ascii
    $s14 = "ction f000(){return \"Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s15 = "{return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})" ascii
    $s16 = "turn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Yz\";})(),(" ascii
    $s17 = "nction f000(){return \"Yz\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return" ascii
    $s18 = "){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(" ascii
    $s19 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"U" ascii
    $s20 = "nction f000(){return \"Br\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DYx\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}