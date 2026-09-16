rule TTP_XOR_QUAD_CurrentVersionRun_5504 {
  strings:
    $key_5504 = { 06 6b [2] 22 65 [2] 09 49 [2] 27 6b [2] 33 70 [2] 3c 6a [2] 22 77 [2] 20 76 [2] 3b 70 [2] 27 77 [2] 3b 58 }

  condition:
    any of them
}