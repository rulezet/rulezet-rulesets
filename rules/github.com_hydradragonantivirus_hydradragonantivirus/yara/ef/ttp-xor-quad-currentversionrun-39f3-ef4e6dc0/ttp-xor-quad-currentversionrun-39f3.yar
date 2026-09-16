rule TTP_XOR_QUAD_CurrentVersionRun_39f3 {
  strings:
    $key_39f3 = { 6a 9c [2] 4e 92 [2] 65 be [2] 4b 9c [2] 5f 87 [2] 50 9d [2] 4e 80 [2] 4c 81 [2] 57 87 [2] 4b 80 [2] 57 af }

  condition:
    any of them
}