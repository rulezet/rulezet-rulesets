rule TTP_XOR_QUAD_CurrentVersionRun_5c9f {
  strings:
    $key_5c9f = { 0f f0 [2] 2b fe [2] 00 d2 [2] 2e f0 [2] 3a eb [2] 35 f1 [2] 2b ec [2] 29 ed [2] 32 eb [2] 2e ec [2] 32 c3 }

  condition:
    any of them
}