rule TTP_XOR_QUAD_CurrentVersionRun_0b16 {
  strings:
    $key_0b16 = { 58 79 [2] 7c 77 [2] 57 5b [2] 79 79 [2] 6d 62 [2] 62 78 [2] 7c 65 [2] 7e 64 [2] 65 62 [2] 79 65 [2] 65 4a }

  condition:
    any of them
}