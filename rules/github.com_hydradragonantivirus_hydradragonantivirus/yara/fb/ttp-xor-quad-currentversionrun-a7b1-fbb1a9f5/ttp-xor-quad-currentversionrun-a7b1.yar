rule TTP_XOR_QUAD_CurrentVersionRun_a7b1 {
  strings:
    $key_a7b1 = { f4 de [2] d0 d0 [2] fb fc [2] d5 de [2] c1 c5 [2] ce df [2] d0 c2 [2] d2 c3 [2] c9 c5 [2] d5 c2 [2] c9 ed }

  condition:
    any of them
}