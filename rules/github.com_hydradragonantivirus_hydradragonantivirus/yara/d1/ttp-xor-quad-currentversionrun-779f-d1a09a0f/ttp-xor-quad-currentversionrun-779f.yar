rule TTP_XOR_QUAD_CurrentVersionRun_779f {
  strings:
    $key_779f = { 24 f0 [2] 00 fe [2] 2b d2 [2] 05 f0 [2] 11 eb [2] 1e f1 [2] 00 ec [2] 02 ed [2] 19 eb [2] 05 ec [2] 19 c3 }

  condition:
    any of them
}