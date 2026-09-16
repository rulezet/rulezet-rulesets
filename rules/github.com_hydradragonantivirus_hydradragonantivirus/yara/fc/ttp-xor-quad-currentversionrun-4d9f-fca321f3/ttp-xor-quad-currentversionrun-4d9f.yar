rule TTP_XOR_QUAD_CurrentVersionRun_4d9f {
  strings:
    $key_4d9f = { 1e f0 [2] 3a fe [2] 11 d2 [2] 3f f0 [2] 2b eb [2] 24 f1 [2] 3a ec [2] 38 ed [2] 23 eb [2] 3f ec [2] 23 c3 }

  condition:
    any of them
}