rule TTP_XOR_QUAD_CurrentVersionRun_7bf8 {
  strings:
    $key_7bf8 = { 28 97 [2] 0c 99 [2] 27 b5 [2] 09 97 [2] 1d 8c [2] 12 96 [2] 0c 8b [2] 0e 8a [2] 15 8c [2] 09 8b [2] 15 a4 }

  condition:
    any of them
}