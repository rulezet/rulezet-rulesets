rule TTP_XOR_QUAD_CurrentVersionRun_5541 {
  strings:
    $key_5541 = { 06 2e [2] 22 20 [2] 09 0c [2] 27 2e [2] 33 35 [2] 3c 2f [2] 22 32 [2] 20 33 [2] 3b 35 [2] 27 32 [2] 3b 1d }

  condition:
    any of them
}