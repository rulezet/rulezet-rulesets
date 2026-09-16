rule TTP_XOR_QUAD_CurrentVersionRun_e57b {
  strings:
    $key_e57b = { b6 14 [2] 92 1a [2] b9 36 [2] 97 14 [2] 83 0f [2] 8c 15 [2] 92 08 [2] 90 09 [2] 8b 0f [2] 97 08 [2] 8b 27 }

  condition:
    any of them
}