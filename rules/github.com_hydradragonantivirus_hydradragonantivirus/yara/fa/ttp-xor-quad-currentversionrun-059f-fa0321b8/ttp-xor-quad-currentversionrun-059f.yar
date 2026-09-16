rule TTP_XOR_QUAD_CurrentVersionRun_059f {
  strings:
    $key_059f = { 56 f0 [2] 72 fe [2] 59 d2 [2] 77 f0 [2] 63 eb [2] 6c f1 [2] 72 ec [2] 70 ed [2] 6b eb [2] 77 ec [2] 6b c3 }

  condition:
    any of them
}