rule TTP_XOR_QUAD_CurrentVersionRun_b99f {
  strings:
    $key_b99f = { ea f0 [2] ce fe [2] e5 d2 [2] cb f0 [2] df eb [2] d0 f1 [2] ce ec [2] cc ed [2] d7 eb [2] cb ec [2] d7 c3 }

  condition:
    any of them
}