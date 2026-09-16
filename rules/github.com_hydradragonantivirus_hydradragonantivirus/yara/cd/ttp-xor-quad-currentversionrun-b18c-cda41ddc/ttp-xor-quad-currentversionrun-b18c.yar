rule TTP_XOR_QUAD_CurrentVersionRun_b18c {
  strings:
    $key_b18c = { e2 e3 [2] c6 ed [2] ed c1 [2] c3 e3 [2] d7 f8 [2] d8 e2 [2] c6 ff [2] c4 fe [2] df f8 [2] c3 ff [2] df d0 }

  condition:
    any of them
}