rule TTP_XOR_QUAD_CurrentVersionRun_6754 {
  strings:
    $key_6754 = { 34 3b [2] 10 35 [2] 3b 19 [2] 15 3b [2] 01 20 [2] 0e 3a [2] 10 27 [2] 12 26 [2] 09 20 [2] 15 27 [2] 09 08 }

  condition:
    any of them
}