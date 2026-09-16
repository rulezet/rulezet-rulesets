rule TTP_XOR_QUAD_CurrentVersionRun_43a2 {
  strings:
    $key_43a2 = { 10 cd [2] 34 c3 [2] 1f ef [2] 31 cd [2] 25 d6 [2] 2a cc [2] 34 d1 [2] 36 d0 [2] 2d d6 [2] 31 d1 [2] 2d fe }

  condition:
    any of them
}