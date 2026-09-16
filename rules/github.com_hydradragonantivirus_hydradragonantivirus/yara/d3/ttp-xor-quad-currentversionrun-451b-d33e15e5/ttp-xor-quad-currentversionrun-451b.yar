rule TTP_XOR_QUAD_CurrentVersionRun_451b {
  strings:
    $key_451b = { 16 74 [2] 32 7a [2] 19 56 [2] 37 74 [2] 23 6f [2] 2c 75 [2] 32 68 [2] 30 69 [2] 2b 6f [2] 37 68 [2] 2b 47 }

  condition:
    any of them
}