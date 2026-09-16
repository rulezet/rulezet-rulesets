rule TTP_XOR_QUAD_CurrentVersionRun_2554 {
  strings:
    $key_2554 = { 76 3b [2] 52 35 [2] 79 19 [2] 57 3b [2] 43 20 [2] 4c 3a [2] 52 27 [2] 50 26 [2] 4b 20 [2] 57 27 [2] 4b 08 }

  condition:
    any of them
}