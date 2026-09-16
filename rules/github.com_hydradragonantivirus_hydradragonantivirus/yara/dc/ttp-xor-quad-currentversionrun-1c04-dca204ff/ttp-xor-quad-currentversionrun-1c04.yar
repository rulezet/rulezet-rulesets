rule TTP_XOR_QUAD_CurrentVersionRun_1c04 {
  strings:
    $key_1c04 = { 4f 6b [2] 6b 65 [2] 40 49 [2] 6e 6b [2] 7a 70 [2] 75 6a [2] 6b 77 [2] 69 76 [2] 72 70 [2] 6e 77 [2] 72 58 }

  condition:
    any of them
}