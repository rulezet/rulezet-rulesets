rule TTP_XOR_QUAD_CurrentVersionRun_8ed0 {
  strings:
    $key_8ed0 = { dd bf [2] f9 b1 [2] d2 9d [2] fc bf [2] e8 a4 [2] e7 be [2] f9 a3 [2] fb a2 [2] e0 a4 [2] fc a3 [2] e0 8c }

  condition:
    any of them
}