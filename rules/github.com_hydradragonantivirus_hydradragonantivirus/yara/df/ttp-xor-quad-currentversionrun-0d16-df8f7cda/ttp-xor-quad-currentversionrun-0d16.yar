rule TTP_XOR_QUAD_CurrentVersionRun_0d16 {
  strings:
    $key_0d16 = { 5e 79 [2] 7a 77 [2] 51 5b [2] 7f 79 [2] 6b 62 [2] 64 78 [2] 7a 65 [2] 78 64 [2] 63 62 [2] 7f 65 [2] 63 4a }

  condition:
    any of them
}