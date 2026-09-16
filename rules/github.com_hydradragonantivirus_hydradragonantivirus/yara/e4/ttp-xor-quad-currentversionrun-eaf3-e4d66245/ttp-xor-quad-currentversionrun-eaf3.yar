rule TTP_XOR_QUAD_CurrentVersionRun_eaf3 {
  strings:
    $key_eaf3 = { b9 9c [2] 9d 92 [2] b6 be [2] 98 9c [2] 8c 87 [2] 83 9d [2] 9d 80 [2] 9f 81 [2] 84 87 [2] 98 80 [2] 84 af }

  condition:
    any of them
}