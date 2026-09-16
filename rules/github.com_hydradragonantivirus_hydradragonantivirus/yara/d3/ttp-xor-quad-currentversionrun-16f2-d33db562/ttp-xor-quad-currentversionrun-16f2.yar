rule TTP_XOR_QUAD_CurrentVersionRun_16f2 {
  strings:
    $key_16f2 = { 45 9d [2] 61 93 [2] 4a bf [2] 64 9d [2] 70 86 [2] 7f 9c [2] 61 81 [2] 63 80 [2] 78 86 [2] 64 81 [2] 78 ae }

  condition:
    any of them
}