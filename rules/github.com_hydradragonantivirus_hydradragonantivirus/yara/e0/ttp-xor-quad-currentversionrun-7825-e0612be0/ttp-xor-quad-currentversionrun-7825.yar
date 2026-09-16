rule TTP_XOR_QUAD_CurrentVersionRun_7825 {
  strings:
    $key_7825 = { 2b 4a [2] 0f 44 [2] 24 68 [2] 0a 4a [2] 1e 51 [2] 11 4b [2] 0f 56 [2] 0d 57 [2] 16 51 [2] 0a 56 [2] 16 79 }

  condition:
    any of them
}