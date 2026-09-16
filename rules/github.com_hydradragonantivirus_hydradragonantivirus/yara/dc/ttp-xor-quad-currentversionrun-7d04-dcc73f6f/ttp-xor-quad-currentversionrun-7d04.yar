rule TTP_XOR_QUAD_CurrentVersionRun_7d04 {
  strings:
    $key_7d04 = { 2e 6b [2] 0a 65 [2] 21 49 [2] 0f 6b [2] 1b 70 [2] 14 6a [2] 0a 77 [2] 08 76 [2] 13 70 [2] 0f 77 [2] 13 58 }

  condition:
    any of them
}