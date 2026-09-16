rule TTP_XOR_QUAD_CurrentVersionRun_6c04 {
  strings:
    $key_6c04 = { 3f 6b [2] 1b 65 [2] 30 49 [2] 1e 6b [2] 0a 70 [2] 05 6a [2] 1b 77 [2] 19 76 [2] 02 70 [2] 1e 77 [2] 02 58 }

  condition:
    any of them
}