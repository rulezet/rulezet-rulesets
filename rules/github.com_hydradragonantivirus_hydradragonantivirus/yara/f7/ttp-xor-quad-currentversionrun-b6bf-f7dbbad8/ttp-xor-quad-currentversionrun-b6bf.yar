rule TTP_XOR_QUAD_CurrentVersionRun_b6bf {
  strings:
    $key_b6bf = { e5 d0 [2] c1 de [2] ea f2 [2] c4 d0 [2] d0 cb [2] df d1 [2] c1 cc [2] c3 cd [2] d8 cb [2] c4 cc [2] d8 e3 }

  condition:
    any of them
}