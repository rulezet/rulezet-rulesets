rule TTP_XOR_QUAD_CurrentVersionRun_b39f {
  strings:
    $key_b39f = { e0 f0 [2] c4 fe [2] ef d2 [2] c1 f0 [2] d5 eb [2] da f1 [2] c4 ec [2] c6 ed [2] dd eb [2] c1 ec [2] dd c3 }

  condition:
    any of them
}