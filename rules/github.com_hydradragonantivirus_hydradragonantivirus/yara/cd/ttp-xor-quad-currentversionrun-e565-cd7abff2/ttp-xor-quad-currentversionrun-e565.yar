rule TTP_XOR_QUAD_CurrentVersionRun_e565 {
  strings:
    $key_e565 = { b6 0a [2] 92 04 [2] b9 28 [2] 97 0a [2] 83 11 [2] 8c 0b [2] 92 16 [2] 90 17 [2] 8b 11 [2] 97 16 [2] 8b 39 }

  condition:
    any of them
}