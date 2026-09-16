rule TTP_XOR_QUAD_CurrentVersionRun_456b {
  strings:
    $key_456b = { 16 04 [2] 32 0a [2] 19 26 [2] 37 04 [2] 23 1f [2] 2c 05 [2] 32 18 [2] 30 19 [2] 2b 1f [2] 37 18 [2] 2b 37 }

  condition:
    any of them
}