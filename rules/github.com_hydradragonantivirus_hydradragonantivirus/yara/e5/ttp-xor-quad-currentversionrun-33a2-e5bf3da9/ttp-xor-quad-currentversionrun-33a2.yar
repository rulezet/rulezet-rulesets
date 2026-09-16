rule TTP_XOR_QUAD_CurrentVersionRun_33a2 {
  strings:
    $key_33a2 = { 60 cd [2] 44 c3 [2] 6f ef [2] 41 cd [2] 55 d6 [2] 5a cc [2] 44 d1 [2] 46 d0 [2] 5d d6 [2] 41 d1 [2] 5d fe }

  condition:
    any of them
}