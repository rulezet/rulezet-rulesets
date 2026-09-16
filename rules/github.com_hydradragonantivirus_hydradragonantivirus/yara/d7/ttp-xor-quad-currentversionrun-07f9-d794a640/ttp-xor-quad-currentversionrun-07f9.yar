rule TTP_XOR_QUAD_CurrentVersionRun_07f9 {
  strings:
    $key_07f9 = { 54 96 [2] 70 98 [2] 5b b4 [2] 75 96 [2] 61 8d [2] 6e 97 [2] 70 8a [2] 72 8b [2] 69 8d [2] 75 8a [2] 69 a5 }

  condition:
    any of them
}