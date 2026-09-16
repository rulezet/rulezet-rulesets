rule TTP_XOR_QUAD_CurrentVersionRun_fbf3 {
  strings:
    $key_fbf3 = { a8 9c [2] 8c 92 [2] a7 be [2] 89 9c [2] 9d 87 [2] 92 9d [2] 8c 80 [2] 8e 81 [2] 95 87 [2] 89 80 [2] 95 af }

  condition:
    any of them
}