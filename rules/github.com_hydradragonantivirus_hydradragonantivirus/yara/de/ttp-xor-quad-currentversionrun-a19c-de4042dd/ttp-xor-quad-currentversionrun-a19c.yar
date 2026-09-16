rule TTP_XOR_QUAD_CurrentVersionRun_a19c {
  strings:
    $key_a19c = { f2 f3 [2] d6 fd [2] fd d1 [2] d3 f3 [2] c7 e8 [2] c8 f2 [2] d6 ef [2] d4 ee [2] cf e8 [2] d3 ef [2] cf c0 }

  condition:
    any of them
}