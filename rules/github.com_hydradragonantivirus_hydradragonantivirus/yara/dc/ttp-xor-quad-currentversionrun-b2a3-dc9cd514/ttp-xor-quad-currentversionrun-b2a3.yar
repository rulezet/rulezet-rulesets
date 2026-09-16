rule TTP_XOR_QUAD_CurrentVersionRun_b2a3 {
  strings:
    $key_b2a3 = { e1 cc [2] c5 c2 [2] ee ee [2] c0 cc [2] d4 d7 [2] db cd [2] c5 d0 [2] c7 d1 [2] dc d7 [2] c0 d0 [2] dc ff }

  condition:
    any of them
}