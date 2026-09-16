rule TTP_XOR_QUAD_CurrentVersionRun_e555 {
  strings:
    $key_e555 = { b6 3a [2] 92 34 [2] b9 18 [2] 97 3a [2] 83 21 [2] 8c 3b [2] 92 26 [2] 90 27 [2] 8b 21 [2] 97 26 [2] 8b 09 }

  condition:
    any of them
}