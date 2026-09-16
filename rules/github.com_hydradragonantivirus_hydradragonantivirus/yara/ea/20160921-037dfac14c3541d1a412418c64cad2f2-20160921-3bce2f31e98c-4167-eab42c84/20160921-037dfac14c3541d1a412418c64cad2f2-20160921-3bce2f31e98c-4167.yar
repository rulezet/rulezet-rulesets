rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_3bce2f31e98c_4167 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash3       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash4       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash5       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){ret" ascii
    $s3 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function " ascii
    $s4 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s5 = "){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}