rule TTP_XOR_QUAD_CurrentVersionRun_41f3 {
  strings:
    $key_41f3 = { 12 9c [2] 36 92 [2] 1d be [2] 33 9c [2] 27 87 [2] 28 9d [2] 36 80 [2] 34 81 [2] 2f 87 [2] 33 80 [2] 2f af }

  condition:
    any of them
}