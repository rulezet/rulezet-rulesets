rule TTP_XOR_QUAD_CurrentVersionRun_41ef {
  strings:
    $key_41ef = { 12 80 [2] 36 8e [2] 1d a2 [2] 33 80 [2] 27 9b [2] 28 81 [2] 36 9c [2] 34 9d [2] 2f 9b [2] 33 9c [2] 2f b3 }

  condition:
    any of them
}