rule TTP_XOR_QUAD_CurrentVersionRun_e536 {
  strings:
    $key_e536 = { b6 59 [2] 92 57 [2] b9 7b [2] 97 59 [2] 83 42 [2] 8c 58 [2] 92 45 [2] 90 44 [2] 8b 42 [2] 97 45 [2] 8b 6a }

  condition:
    any of them
}