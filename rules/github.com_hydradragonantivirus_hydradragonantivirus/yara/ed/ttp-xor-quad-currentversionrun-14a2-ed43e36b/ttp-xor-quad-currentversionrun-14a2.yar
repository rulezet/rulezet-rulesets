rule TTP_XOR_QUAD_CurrentVersionRun_14a2 {
  strings:
    $key_14a2 = { 47 cd [2] 63 c3 [2] 48 ef [2] 66 cd [2] 72 d6 [2] 7d cc [2] 63 d1 [2] 61 d0 [2] 7a d6 [2] 66 d1 [2] 7a fe }

  condition:
    any of them
}