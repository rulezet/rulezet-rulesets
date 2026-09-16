rule TTP_XOR_QUAD_CurrentVersionRun_e566 {
  strings:
    $key_e566 = { b6 09 [2] 92 07 [2] b9 2b [2] 97 09 [2] 83 12 [2] 8c 08 [2] 92 15 [2] 90 14 [2] 8b 12 [2] 97 15 [2] 8b 3a }

  condition:
    any of them
}