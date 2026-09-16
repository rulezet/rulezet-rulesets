rule TTP_XOR_QUAD_CurrentVersionRun_1936 {
  strings:
    $key_1936 = { 4a 59 [2] 6e 57 [2] 45 7b [2] 6b 59 [2] 7f 42 [2] 70 58 [2] 6e 45 [2] 6c 44 [2] 77 42 [2] 6b 45 [2] 77 6a }

  condition:
    any of them
}