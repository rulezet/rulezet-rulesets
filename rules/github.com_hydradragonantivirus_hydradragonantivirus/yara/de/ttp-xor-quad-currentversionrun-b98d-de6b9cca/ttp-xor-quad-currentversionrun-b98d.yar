rule TTP_XOR_QUAD_CurrentVersionRun_b98d {
  strings:
    $key_b98d = { ea e2 [2] ce ec [2] e5 c0 [2] cb e2 [2] df f9 [2] d0 e3 [2] ce fe [2] cc ff [2] d7 f9 [2] cb fe [2] d7 d1 }

  condition:
    any of them
}