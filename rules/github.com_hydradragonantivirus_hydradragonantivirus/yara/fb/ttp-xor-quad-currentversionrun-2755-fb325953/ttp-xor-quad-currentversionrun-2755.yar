rule TTP_XOR_QUAD_CurrentVersionRun_2755 {
  strings:
    $key_2755 = { 74 3a [2] 50 34 [2] 7b 18 [2] 55 3a [2] 41 21 [2] 4e 3b [2] 50 26 [2] 52 27 [2] 49 21 [2] 55 26 [2] 49 09 }

  condition:
    any of them
}