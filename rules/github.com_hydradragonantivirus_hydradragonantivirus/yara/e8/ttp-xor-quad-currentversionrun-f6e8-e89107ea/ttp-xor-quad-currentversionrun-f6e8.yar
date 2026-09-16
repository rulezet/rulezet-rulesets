rule TTP_XOR_QUAD_CurrentVersionRun_f6e8 {
  strings:
    $key_f6e8 = { a5 87 [2] 81 89 [2] aa a5 [2] 84 87 [2] 90 9c [2] 9f 86 [2] 81 9b [2] 83 9a [2] 98 9c [2] 84 9b [2] 98 b4 }

  condition:
    any of them
}