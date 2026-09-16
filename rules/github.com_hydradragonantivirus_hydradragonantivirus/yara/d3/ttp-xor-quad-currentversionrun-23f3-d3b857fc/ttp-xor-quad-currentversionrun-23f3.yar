rule TTP_XOR_QUAD_CurrentVersionRun_23f3 {
  strings:
    $key_23f3 = { 70 9c [2] 54 92 [2] 7f be [2] 51 9c [2] 45 87 [2] 4a 9d [2] 54 80 [2] 56 81 [2] 4d 87 [2] 51 80 [2] 4d af }

  condition:
    any of them
}