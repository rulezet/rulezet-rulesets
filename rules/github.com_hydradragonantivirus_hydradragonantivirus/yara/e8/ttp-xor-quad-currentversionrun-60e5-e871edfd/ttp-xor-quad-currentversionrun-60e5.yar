rule TTP_XOR_QUAD_CurrentVersionRun_60e5 {
  strings:
    $key_60e5 = { 33 8a [2] 17 84 [2] 3c a8 [2] 12 8a [2] 06 91 [2] 09 8b [2] 17 96 [2] 15 97 [2] 0e 91 [2] 12 96 [2] 0e b9 }

  condition:
    any of them
}