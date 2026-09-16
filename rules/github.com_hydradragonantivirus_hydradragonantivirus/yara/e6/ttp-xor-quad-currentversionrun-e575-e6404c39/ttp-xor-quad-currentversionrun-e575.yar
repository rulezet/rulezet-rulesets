rule TTP_XOR_QUAD_CurrentVersionRun_e575 {
  strings:
    $key_e575 = { b6 1a [2] 92 14 [2] b9 38 [2] 97 1a [2] 83 01 [2] 8c 1b [2] 92 06 [2] 90 07 [2] 8b 01 [2] 97 06 [2] 8b 29 }

  condition:
    any of them
}