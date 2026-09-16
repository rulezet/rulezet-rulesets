rule TTP_XOR_QUAD_CurrentVersionRun_6841 {
  strings:
    $key_6841 = { 3b 2e [2] 1f 20 [2] 34 0c [2] 1a 2e [2] 0e 35 [2] 01 2f [2] 1f 32 [2] 1d 33 [2] 06 35 [2] 1a 32 [2] 06 1d }

  condition:
    any of them
}