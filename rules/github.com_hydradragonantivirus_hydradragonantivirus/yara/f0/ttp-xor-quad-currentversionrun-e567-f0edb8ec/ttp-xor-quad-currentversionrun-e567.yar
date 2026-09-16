rule TTP_XOR_QUAD_CurrentVersionRun_e567 {
  strings:
    $key_e567 = { b6 08 [2] 92 06 [2] b9 2a [2] 97 08 [2] 83 13 [2] 8c 09 [2] 92 14 [2] 90 15 [2] 8b 13 [2] 97 14 [2] 8b 3b }

  condition:
    any of them
}