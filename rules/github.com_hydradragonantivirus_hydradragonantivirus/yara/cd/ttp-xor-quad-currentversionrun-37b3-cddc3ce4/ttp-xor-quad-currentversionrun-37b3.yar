rule TTP_XOR_QUAD_CurrentVersionRun_37b3 {
  strings:
    $key_37b3 = { 64 dc [2] 40 d2 [2] 6b fe [2] 45 dc [2] 51 c7 [2] 5e dd [2] 40 c0 [2] 42 c1 [2] 59 c7 [2] 45 c0 [2] 59 ef }

  condition:
    any of them
}