rule TTP_XOR_QUAD_CurrentVersionRun_1946 {
  strings:
    $key_1946 = { 4a 29 [2] 6e 27 [2] 45 0b [2] 6b 29 [2] 7f 32 [2] 70 28 [2] 6e 35 [2] 6c 34 [2] 77 32 [2] 6b 35 [2] 77 1a }

  condition:
    any of them
}