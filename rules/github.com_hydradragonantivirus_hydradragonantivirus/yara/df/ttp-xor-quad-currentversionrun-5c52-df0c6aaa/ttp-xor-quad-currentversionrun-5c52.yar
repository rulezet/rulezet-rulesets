rule TTP_XOR_QUAD_CurrentVersionRun_5c52 {
  strings:
    $key_5c52 = { 0f 3d [2] 2b 33 [2] 00 1f [2] 2e 3d [2] 3a 26 [2] 35 3c [2] 2b 21 [2] 29 20 [2] 32 26 [2] 2e 21 [2] 32 0e }

  condition:
    any of them
}