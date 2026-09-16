rule TTP_XOR_QUAD_CurrentVersionRun_7924 {
  strings:
    $key_7924 = { 2a 4b [2] 0e 45 [2] 25 69 [2] 0b 4b [2] 1f 50 [2] 10 4a [2] 0e 57 [2] 0c 56 [2] 17 50 [2] 0b 57 [2] 17 78 }

  condition:
    any of them
}