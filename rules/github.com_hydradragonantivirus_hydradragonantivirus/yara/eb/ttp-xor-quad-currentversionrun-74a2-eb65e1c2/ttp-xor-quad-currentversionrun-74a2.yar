rule TTP_XOR_QUAD_CurrentVersionRun_74a2 {
  strings:
    $key_74a2 = { 27 cd [2] 03 c3 [2] 28 ef [2] 06 cd [2] 12 d6 [2] 1d cc [2] 03 d1 [2] 01 d0 [2] 1a d6 [2] 06 d1 [2] 1a fe }

  condition:
    any of them
}