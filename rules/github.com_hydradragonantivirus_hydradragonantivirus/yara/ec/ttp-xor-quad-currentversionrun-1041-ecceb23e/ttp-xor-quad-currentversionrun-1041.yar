rule TTP_XOR_QUAD_CurrentVersionRun_1041 {
  strings:
    $key_1041 = { 43 2e [2] 67 20 [2] 4c 0c [2] 62 2e [2] 76 35 [2] 79 2f [2] 67 32 [2] 65 33 [2] 7e 35 [2] 62 32 [2] 7e 1d }

  condition:
    any of them
}