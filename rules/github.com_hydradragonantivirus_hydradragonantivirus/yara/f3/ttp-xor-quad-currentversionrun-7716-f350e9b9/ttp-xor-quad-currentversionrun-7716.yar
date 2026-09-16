rule TTP_XOR_QUAD_CurrentVersionRun_7716 {
  strings:
    $key_7716 = { 24 79 [2] 00 77 [2] 2b 5b [2] 05 79 [2] 11 62 [2] 1e 78 [2] 00 65 [2] 02 64 [2] 19 62 [2] 05 65 [2] 19 4a }

  condition:
    any of them
}