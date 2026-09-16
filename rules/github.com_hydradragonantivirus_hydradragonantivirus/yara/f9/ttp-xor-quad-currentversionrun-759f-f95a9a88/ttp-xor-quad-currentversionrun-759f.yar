rule TTP_XOR_QUAD_CurrentVersionRun_759f {
  strings:
    $key_759f = { 26 f0 [2] 02 fe [2] 29 d2 [2] 07 f0 [2] 13 eb [2] 1c f1 [2] 02 ec [2] 00 ed [2] 1b eb [2] 07 ec [2] 1b c3 }

  condition:
    any of them
}