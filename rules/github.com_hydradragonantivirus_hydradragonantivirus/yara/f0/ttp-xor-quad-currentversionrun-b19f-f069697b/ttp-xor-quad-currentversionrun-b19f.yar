rule TTP_XOR_QUAD_CurrentVersionRun_b19f {
  strings:
    $key_b19f = { e2 f0 [2] c6 fe [2] ed d2 [2] c3 f0 [2] d7 eb [2] d8 f1 [2] c6 ec [2] c4 ed [2] df eb [2] c3 ec [2] df c3 }

  condition:
    any of them
}