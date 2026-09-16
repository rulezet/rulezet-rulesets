rule TTP_XOR_QUAD_CurrentVersionRun_52a2 {
  strings:
    $key_52a2 = { 01 cd [2] 25 c3 [2] 0e ef [2] 20 cd [2] 34 d6 [2] 3b cc [2] 25 d1 [2] 27 d0 [2] 3c d6 [2] 20 d1 [2] 3c fe }

  condition:
    any of them
}