rule TTP_XOR_QUAD_CurrentVersionRun_6f41 {
  strings:
    $key_6f41 = { 3c 2e [2] 18 20 [2] 33 0c [2] 1d 2e [2] 09 35 [2] 06 2f [2] 18 32 [2] 1a 33 [2] 01 35 [2] 1d 32 [2] 01 1d }

  condition:
    any of them
}