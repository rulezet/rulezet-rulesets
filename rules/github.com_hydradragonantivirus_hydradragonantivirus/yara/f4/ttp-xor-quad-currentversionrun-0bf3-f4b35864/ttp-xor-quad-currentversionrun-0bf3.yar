rule TTP_XOR_QUAD_CurrentVersionRun_0bf3 {
  strings:
    $key_0bf3 = { 58 9c [2] 7c 92 [2] 57 be [2] 79 9c [2] 6d 87 [2] 62 9d [2] 7c 80 [2] 7e 81 [2] 65 87 [2] 79 80 [2] 65 af }

  condition:
    any of them
}