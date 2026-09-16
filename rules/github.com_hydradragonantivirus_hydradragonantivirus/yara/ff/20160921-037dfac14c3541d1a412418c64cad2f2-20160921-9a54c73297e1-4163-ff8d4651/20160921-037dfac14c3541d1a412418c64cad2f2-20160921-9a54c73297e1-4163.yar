rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_9a54c73297e1_4163 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash4       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "n \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(fun" ascii
    $s2 = "00(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\"" ascii
    $s3 = "unction f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s4 = "j\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s5 = "n f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}