rule TTP_XOR_QUAD_CurrentVersionRun_5ff3 {
  strings:
    $key_5ff3 = { 0c 9c [2] 28 92 [2] 03 be [2] 2d 9c [2] 39 87 [2] 36 9d [2] 28 80 [2] 2a 81 [2] 31 87 [2] 2d 80 [2] 31 af }

  condition:
    any of them
}