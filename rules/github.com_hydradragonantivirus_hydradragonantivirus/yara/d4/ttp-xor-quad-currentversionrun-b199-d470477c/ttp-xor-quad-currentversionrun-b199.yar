rule TTP_XOR_QUAD_CurrentVersionRun_b199 {
  strings:
    $key_b199 = { e2 f6 [2] c6 f8 [2] ed d4 [2] c3 f6 [2] d7 ed [2] d8 f7 [2] c6 ea [2] c4 eb [2] df ed [2] c3 ea [2] df c5 }

  condition:
    any of them
}