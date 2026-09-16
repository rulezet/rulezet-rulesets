rule TTP_XOR_QUAD_CurrentVersionRun_07f3 {
  strings:
    $key_07f3 = { 54 9c [2] 70 92 [2] 5b be [2] 75 9c [2] 61 87 [2] 6e 9d [2] 70 80 [2] 72 81 [2] 69 87 [2] 75 80 [2] 69 af }

  condition:
    any of them
}