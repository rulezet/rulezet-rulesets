rule TTP_XOR_QUAD_CurrentVersionRun_b198 {
  strings:
    $key_b198 = { e2 f7 [2] c6 f9 [2] ed d5 [2] c3 f7 [2] d7 ec [2] d8 f6 [2] c6 eb [2] c4 ea [2] df ec [2] c3 eb [2] df c4 }

  condition:
    any of them
}