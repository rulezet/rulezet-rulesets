rule TTP_XOR_QUAD_CurrentVersionRun_039f {
  strings:
    $key_039f = { 50 f0 [2] 74 fe [2] 5f d2 [2] 71 f0 [2] 65 eb [2] 6a f1 [2] 74 ec [2] 76 ed [2] 6d eb [2] 71 ec [2] 6d c3 }

  condition:
    any of them
}