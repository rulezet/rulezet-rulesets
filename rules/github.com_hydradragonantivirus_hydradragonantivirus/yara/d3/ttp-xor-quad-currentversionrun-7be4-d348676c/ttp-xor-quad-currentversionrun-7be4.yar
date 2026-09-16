rule TTP_XOR_QUAD_CurrentVersionRun_7be4 {
  strings:
    $key_7be4 = { 28 8b [2] 0c 85 [2] 27 a9 [2] 09 8b [2] 1d 90 [2] 12 8a [2] 0c 97 [2] 0e 96 [2] 15 90 [2] 09 97 [2] 15 b8 }

  condition:
    any of them
}