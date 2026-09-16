rule TTP_XOR_QUAD_CurrentVersionRun_b6b8 {
  strings:
    $key_b6b8 = { e5 d7 [2] c1 d9 [2] ea f5 [2] c4 d7 [2] d0 cc [2] df d6 [2] c1 cb [2] c3 ca [2] d8 cc [2] c4 cb [2] d8 e4 }

  condition:
    any of them
}