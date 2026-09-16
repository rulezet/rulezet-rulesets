rule TTP_XOR_QUAD_CurrentVersionRun_6541 {
  strings:
    $key_6541 = { 36 2e [2] 12 20 [2] 39 0c [2] 17 2e [2] 03 35 [2] 0c 2f [2] 12 32 [2] 10 33 [2] 0b 35 [2] 17 32 [2] 0b 1d }

  condition:
    any of them
}