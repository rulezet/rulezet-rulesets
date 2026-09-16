rule TTP_XOR_QUAD_CurrentVersionRun_0c16 {
  strings:
    $key_0c16 = { 5f 79 [2] 7b 77 [2] 50 5b [2] 7e 79 [2] 6a 62 [2] 65 78 [2] 7b 65 [2] 79 64 [2] 62 62 [2] 7e 65 [2] 62 4a }

  condition:
    any of them
}