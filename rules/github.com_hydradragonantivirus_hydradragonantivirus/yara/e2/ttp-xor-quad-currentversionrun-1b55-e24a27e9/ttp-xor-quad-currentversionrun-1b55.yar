rule TTP_XOR_QUAD_CurrentVersionRun_1b55 {
  strings:
    $key_1b55 = { 48 3a [2] 6c 34 [2] 47 18 [2] 69 3a [2] 7d 21 [2] 72 3b [2] 6c 26 [2] 6e 27 [2] 75 21 [2] 69 26 [2] 75 09 }

  condition:
    any of them
}