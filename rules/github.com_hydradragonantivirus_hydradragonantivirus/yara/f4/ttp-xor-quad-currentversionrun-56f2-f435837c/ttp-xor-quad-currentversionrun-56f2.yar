rule TTP_XOR_QUAD_CurrentVersionRun_56f2 {
  strings:
    $key_56f2 = { 05 9d [2] 21 93 [2] 0a bf [2] 24 9d [2] 30 86 [2] 3f 9c [2] 21 81 [2] 23 80 [2] 38 86 [2] 24 81 [2] 38 ae }

  condition:
    any of them
}