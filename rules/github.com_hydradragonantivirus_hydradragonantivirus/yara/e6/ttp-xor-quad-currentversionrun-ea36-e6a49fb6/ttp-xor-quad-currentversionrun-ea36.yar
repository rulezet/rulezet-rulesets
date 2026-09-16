rule TTP_XOR_QUAD_CurrentVersionRun_ea36 {
  strings:
    $key_ea36 = { b9 59 [2] 9d 57 [2] b6 7b [2] 98 59 [2] 8c 42 [2] 83 58 [2] 9d 45 [2] 9f 44 [2] 84 42 [2] 98 45 [2] 84 6a }

  condition:
    any of them
}