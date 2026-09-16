rule TTP_XOR_QUAD_CurrentVersionRun_e3a2 {
  strings:
    $key_e3a2 = { b0 cd [2] 94 c3 [2] bf ef [2] 91 cd [2] 85 d6 [2] 8a cc [2] 94 d1 [2] 96 d0 [2] 8d d6 [2] 91 d1 [2] 8d fe }

  condition:
    any of them
}