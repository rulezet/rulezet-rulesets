rule TTP_XOR_QUAD_CurrentVersionRun_d1f3 {
  strings:
    $key_d1f3 = { 82 9c [2] a6 92 [2] 8d be [2] a3 9c [2] b7 87 [2] b8 9d [2] a6 80 [2] a4 81 [2] bf 87 [2] a3 80 [2] bf af }

  condition:
    any of them
}