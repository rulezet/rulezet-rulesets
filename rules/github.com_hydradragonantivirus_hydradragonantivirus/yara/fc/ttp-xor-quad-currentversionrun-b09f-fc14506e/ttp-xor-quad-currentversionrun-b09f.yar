rule TTP_XOR_QUAD_CurrentVersionRun_b09f {
  strings:
    $key_b09f = { e3 f0 [2] c7 fe [2] ec d2 [2] c2 f0 [2] d6 eb [2] d9 f1 [2] c7 ec [2] c5 ed [2] de eb [2] c2 ec [2] de c3 }

  condition:
    any of them
}