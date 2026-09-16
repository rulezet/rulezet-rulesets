rule TTP_XOR_QUAD_CurrentVersionRun_43f3 {
  strings:
    $key_43f3 = { 10 9c [2] 34 92 [2] 1f be [2] 31 9c [2] 25 87 [2] 2a 9d [2] 34 80 [2] 36 81 [2] 2d 87 [2] 31 80 [2] 2d af }

  condition:
    any of them
}