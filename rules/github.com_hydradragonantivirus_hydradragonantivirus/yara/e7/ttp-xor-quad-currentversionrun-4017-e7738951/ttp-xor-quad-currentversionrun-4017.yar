rule TTP_XOR_QUAD_CurrentVersionRun_4017 {
  strings:
    $key_4017 = { 13 78 [2] 37 76 [2] 1c 5a [2] 32 78 [2] 26 63 [2] 29 79 [2] 37 64 [2] 35 65 [2] 2e 63 [2] 32 64 [2] 2e 4b }

  condition:
    any of them
}