rule TTP_XOR_QUAD_CurrentVersionRun_4616 {
  strings:
    $key_4616 = { 15 79 [2] 31 77 [2] 1a 5b [2] 34 79 [2] 20 62 [2] 2f 78 [2] 31 65 [2] 33 64 [2] 28 62 [2] 34 65 [2] 28 4a }

  condition:
    any of them
}