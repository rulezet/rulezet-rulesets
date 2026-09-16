rule TTP_XOR_QUAD_CurrentVersionRun_1904 {
  strings:
    $key_1904 = { 4a 6b [2] 6e 65 [2] 45 49 [2] 6b 6b [2] 7f 70 [2] 70 6a [2] 6e 77 [2] 6c 76 [2] 77 70 [2] 6b 77 [2] 77 58 }

  condition:
    any of them
}