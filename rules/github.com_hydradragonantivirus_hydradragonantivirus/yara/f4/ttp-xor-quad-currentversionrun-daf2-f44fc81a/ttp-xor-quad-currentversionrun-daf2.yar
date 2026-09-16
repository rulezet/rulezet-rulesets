rule TTP_XOR_QUAD_CurrentVersionRun_daf2 {
  strings:
    $key_daf2 = { 89 9d [2] ad 93 [2] 86 bf [2] a8 9d [2] bc 86 [2] b3 9c [2] ad 81 [2] af 80 [2] b4 86 [2] a8 81 [2] b4 ae }

  condition:
    any of them
}