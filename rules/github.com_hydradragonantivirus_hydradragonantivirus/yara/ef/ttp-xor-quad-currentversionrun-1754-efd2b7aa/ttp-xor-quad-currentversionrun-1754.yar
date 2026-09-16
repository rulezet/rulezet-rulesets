rule TTP_XOR_QUAD_CurrentVersionRun_1754 {
  strings:
    $key_1754 = { 44 3b [2] 60 35 [2] 4b 19 [2] 65 3b [2] 71 20 [2] 7e 3a [2] 60 27 [2] 62 26 [2] 79 20 [2] 65 27 [2] 79 08 }

  condition:
    any of them
}