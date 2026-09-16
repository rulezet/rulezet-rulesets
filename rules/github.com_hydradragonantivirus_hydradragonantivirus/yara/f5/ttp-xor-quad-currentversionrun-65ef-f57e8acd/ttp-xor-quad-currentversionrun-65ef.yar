rule TTP_XOR_QUAD_CurrentVersionRun_65ef {
  strings:
    $key_65ef = { 36 80 [2] 12 8e [2] 39 a2 [2] 17 80 [2] 03 9b [2] 0c 81 [2] 12 9c [2] 10 9d [2] 0b 9b [2] 17 9c [2] 0b b3 }

  condition:
    any of them
}