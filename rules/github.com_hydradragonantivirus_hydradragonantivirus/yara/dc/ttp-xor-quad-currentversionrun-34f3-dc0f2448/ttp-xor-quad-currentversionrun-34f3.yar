rule TTP_XOR_QUAD_CurrentVersionRun_34f3 {
  strings:
    $key_34f3 = { 67 9c [2] 43 92 [2] 68 be [2] 46 9c [2] 52 87 [2] 5d 9d [2] 43 80 [2] 41 81 [2] 5a 87 [2] 46 80 [2] 5a af }

  condition:
    any of them
}