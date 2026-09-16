rule TTP_XOR_QUAD_CurrentVersionRun_4060 {
  strings:
    $key_4060 = { 13 0f [2] 37 01 [2] 1c 2d [2] 32 0f [2] 26 14 [2] 29 0e [2] 37 13 [2] 35 12 [2] 2e 14 [2] 32 13 [2] 2e 3c }

  condition:
    any of them
}