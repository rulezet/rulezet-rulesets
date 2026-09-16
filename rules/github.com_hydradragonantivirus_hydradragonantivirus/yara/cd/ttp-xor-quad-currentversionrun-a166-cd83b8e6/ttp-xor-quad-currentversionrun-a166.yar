rule TTP_XOR_QUAD_CurrentVersionRun_a166 {
  strings:
    $key_a166 = { f2 09 [2] d6 07 [2] fd 2b [2] d3 09 [2] c7 12 [2] c8 08 [2] d6 15 [2] d4 14 [2] cf 12 [2] d3 15 [2] cf 3a }

  condition:
    any of them
}