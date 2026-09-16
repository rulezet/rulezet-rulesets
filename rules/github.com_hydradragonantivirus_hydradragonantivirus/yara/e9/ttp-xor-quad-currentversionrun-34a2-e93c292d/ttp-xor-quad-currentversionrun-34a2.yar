rule TTP_XOR_QUAD_CurrentVersionRun_34a2 {
  strings:
    $key_34a2 = { 67 cd [2] 43 c3 [2] 68 ef [2] 46 cd [2] 52 d6 [2] 5d cc [2] 43 d1 [2] 41 d0 [2] 5a d6 [2] 46 d1 [2] 5a fe }

  condition:
    any of them
}