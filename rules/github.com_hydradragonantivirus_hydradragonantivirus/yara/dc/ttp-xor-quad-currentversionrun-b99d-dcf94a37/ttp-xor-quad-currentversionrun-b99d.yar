rule TTP_XOR_QUAD_CurrentVersionRun_b99d {
  strings:
    $key_b99d = { ea f2 [2] ce fc [2] e5 d0 [2] cb f2 [2] df e9 [2] d0 f3 [2] ce ee [2] cc ef [2] d7 e9 [2] cb ee [2] d7 c1 }

  condition:
    any of them
}