rule TTP_XOR_QUAD_CurrentVersionRun_27f3 {
  strings:
    $key_27f3 = { 74 9c [2] 50 92 [2] 7b be [2] 55 9c [2] 41 87 [2] 4e 9d [2] 50 80 [2] 52 81 [2] 49 87 [2] 55 80 [2] 49 af }

  condition:
    any of them
}