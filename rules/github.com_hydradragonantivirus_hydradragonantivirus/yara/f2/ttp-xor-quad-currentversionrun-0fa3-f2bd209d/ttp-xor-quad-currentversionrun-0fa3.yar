rule TTP_XOR_QUAD_CurrentVersionRun_0fa3 {
  strings:
    $key_0fa3 = { 5c cc [2] 78 c2 [2] 53 ee [2] 7d cc [2] 69 d7 [2] 66 cd [2] 78 d0 [2] 7a d1 [2] 61 d7 [2] 7d d0 [2] 61 ff }

  condition:
    any of them
}