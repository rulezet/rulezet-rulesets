rule TTP_XOR_QUAD_CurrentVersionRun_1704 {
  strings:
    $key_1704 = { 44 6b [2] 60 65 [2] 4b 49 [2] 65 6b [2] 71 70 [2] 7e 6a [2] 60 77 [2] 62 76 [2] 79 70 [2] 65 77 [2] 79 58 }

  condition:
    any of them
}