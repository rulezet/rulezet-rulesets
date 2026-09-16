rule TTP_XOR_QUAD_CurrentVersionRun_19e4 {
  strings:
    $key_19e4 = { 4a 8b [2] 6e 85 [2] 45 a9 [2] 6b 8b [2] 7f 90 [2] 70 8a [2] 6e 97 [2] 6c 96 [2] 77 90 [2] 6b 97 [2] 77 b8 }

  condition:
    any of them
}