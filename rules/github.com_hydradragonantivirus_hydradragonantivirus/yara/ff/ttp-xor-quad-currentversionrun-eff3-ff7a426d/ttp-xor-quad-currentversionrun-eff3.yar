rule TTP_XOR_QUAD_CurrentVersionRun_eff3 {
  strings:
    $key_eff3 = { bc 9c [2] 98 92 [2] b3 be [2] 9d 9c [2] 89 87 [2] 86 9d [2] 98 80 [2] 9a 81 [2] 81 87 [2] 9d 80 [2] 81 af }

  condition:
    any of them
}