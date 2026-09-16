rule TTP_XOR_QUAD_CurrentVersionRun_b2a2 {
  strings:
    $key_b2a2 = { e1 cd [2] c5 c3 [2] ee ef [2] c0 cd [2] d4 d6 [2] db cc [2] c5 d1 [2] c7 d0 [2] dc d6 [2] c0 d1 [2] dc fe }

  condition:
    any of them
}