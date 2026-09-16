rule TTP_XOR_QUAD_CurrentVersionRun_22f2 {
  strings:
    $key_22f2 = { 71 9d [2] 55 93 [2] 7e bf [2] 50 9d [2] 44 86 [2] 4b 9c [2] 55 81 [2] 57 80 [2] 4c 86 [2] 50 81 [2] 4c ae }

  condition:
    any of them
}