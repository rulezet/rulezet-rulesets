rule TTP_XOR_QUAD_CurrentVersionRun_31f3 {
  strings:
    $key_31f3 = { 62 9c [2] 46 92 [2] 6d be [2] 43 9c [2] 57 87 [2] 58 9d [2] 46 80 [2] 44 81 [2] 5f 87 [2] 43 80 [2] 5f af }

  condition:
    any of them
}