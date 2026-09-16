rule TTP_XOR_QUAD_CurrentVersionRun_079f {
  strings:
    $key_079f = { 54 f0 [2] 70 fe [2] 5b d2 [2] 75 f0 [2] 61 eb [2] 6e f1 [2] 70 ec [2] 72 ed [2] 69 eb [2] 75 ec [2] 69 c3 }

  condition:
    any of them
}