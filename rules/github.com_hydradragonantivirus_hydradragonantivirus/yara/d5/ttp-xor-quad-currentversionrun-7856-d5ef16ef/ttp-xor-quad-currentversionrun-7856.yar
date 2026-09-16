rule TTP_XOR_QUAD_CurrentVersionRun_7856 {
  strings:
    $key_7856 = { 2b 39 [2] 0f 37 [2] 24 1b [2] 0a 39 [2] 1e 22 [2] 11 38 [2] 0f 25 [2] 0d 24 [2] 16 22 [2] 0a 25 [2] 16 0a }

  condition:
    any of them
}