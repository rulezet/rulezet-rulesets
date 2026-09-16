rule TTP_XOR_QUAD_CurrentVersionRun_57b3 {
  strings:
    $key_57b3 = { 04 dc [2] 20 d2 [2] 0b fe [2] 25 dc [2] 31 c7 [2] 3e dd [2] 20 c0 [2] 22 c1 [2] 39 c7 [2] 25 c0 [2] 39 ef }

  condition:
    any of them
}