rule TTP_XOR_QUAD_CurrentVersionRun_f3a2 {
  strings:
    $key_f3a2 = { a0 cd [2] 84 c3 [2] af ef [2] 81 cd [2] 95 d6 [2] 9a cc [2] 84 d1 [2] 86 d0 [2] 9d d6 [2] 81 d1 [2] 9d fe }

  condition:
    any of them
}