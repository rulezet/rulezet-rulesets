rule TTP_XOR_QUAD_CurrentVersionRun_7844 {
  strings:
    $key_7844 = { 2b 2b [2] 0f 25 [2] 24 09 [2] 0a 2b [2] 1e 30 [2] 11 2a [2] 0f 37 [2] 0d 36 [2] 16 30 [2] 0a 37 [2] 16 18 }

  condition:
    any of them
}