rule TTP_XOR_QUAD_CurrentVersionRun_6041 {
  strings:
    $key_6041 = { 33 2e [2] 17 20 [2] 3c 0c [2] 12 2e [2] 06 35 [2] 09 2f [2] 17 32 [2] 15 33 [2] 0e 35 [2] 12 32 [2] 0e 1d }

  condition:
    any of them
}