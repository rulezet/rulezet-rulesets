rule TTP_XOR_QUAD_CurrentVersionRun_73f8 {
  strings:
    $key_73f8 = { 20 97 [2] 04 99 [2] 2f b5 [2] 01 97 [2] 15 8c [2] 1a 96 [2] 04 8b [2] 06 8a [2] 1d 8c [2] 01 8b [2] 1d a4 }

  condition:
    any of them
}