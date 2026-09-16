rule TTP_XOR_QUAD_CurrentVersionRun_a79f {
  strings:
    $key_a79f = { f4 f0 [2] d0 fe [2] fb d2 [2] d5 f0 [2] c1 eb [2] ce f1 [2] d0 ec [2] d2 ed [2] c9 eb [2] d5 ec [2] c9 c3 }

  condition:
    any of them
}