rule TTP_XOR_QUAD_CurrentVersionRun_0c05 {
  strings:
    $key_0c05 = { 5f 6a [2] 7b 64 [2] 50 48 [2] 7e 6a [2] 6a 71 [2] 65 6b [2] 7b 76 [2] 79 77 [2] 62 71 [2] 7e 76 [2] 62 59 }

  condition:
    any of them
}