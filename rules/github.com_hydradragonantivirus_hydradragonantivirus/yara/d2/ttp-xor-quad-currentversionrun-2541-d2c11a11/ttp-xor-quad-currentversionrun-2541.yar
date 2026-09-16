rule TTP_XOR_QUAD_CurrentVersionRun_2541 {
  strings:
    $key_2541 = { 76 2e [2] 52 20 [2] 79 0c [2] 57 2e [2] 43 35 [2] 4c 2f [2] 52 32 [2] 50 33 [2] 4b 35 [2] 57 32 [2] 4b 1d }

  condition:
    any of them
}