rule TTP_XOR_QUAD_CurrentVersionRun_5d9f {
  strings:
    $key_5d9f = { 0e f0 [2] 2a fe [2] 01 d2 [2] 2f f0 [2] 3b eb [2] 34 f1 [2] 2a ec [2] 28 ed [2] 33 eb [2] 2f ec [2] 33 c3 }

  condition:
    any of them
}