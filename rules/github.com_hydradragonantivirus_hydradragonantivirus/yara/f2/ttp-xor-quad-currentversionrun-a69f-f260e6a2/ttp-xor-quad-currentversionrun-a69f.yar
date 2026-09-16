rule TTP_XOR_QUAD_CurrentVersionRun_a69f {
  strings:
    $key_a69f = { f5 f0 [2] d1 fe [2] fa d2 [2] d4 f0 [2] c0 eb [2] cf f1 [2] d1 ec [2] d3 ed [2] c8 eb [2] d4 ec [2] c8 c3 }

  condition:
    any of them
}