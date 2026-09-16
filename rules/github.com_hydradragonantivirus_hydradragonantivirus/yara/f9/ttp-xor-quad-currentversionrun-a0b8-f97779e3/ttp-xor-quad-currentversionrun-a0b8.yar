rule TTP_XOR_QUAD_CurrentVersionRun_a0b8 {
  strings:
    $key_a0b8 = { f3 d7 [2] d7 d9 [2] fc f5 [2] d2 d7 [2] c6 cc [2] c9 d6 [2] d7 cb [2] d5 ca [2] ce cc [2] d2 cb [2] ce e4 }

  condition:
    any of them
}