rule TTP_XOR_QUAD_CurrentVersionRun_5846 {
  strings:
    $key_5846 = { 0b 29 [2] 2f 27 [2] 04 0b [2] 2a 29 [2] 3e 32 [2] 31 28 [2] 2f 35 [2] 2d 34 [2] 36 32 [2] 2a 35 [2] 36 1a }

  condition:
    any of them
}