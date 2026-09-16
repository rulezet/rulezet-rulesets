rule TTP_XOR_QUAD_CurrentVersionRun_89b1 {
  strings:
    $key_89b1 = { da de [2] fe d0 [2] d5 fc [2] fb de [2] ef c5 [2] e0 df [2] fe c2 [2] fc c3 [2] e7 c5 [2] fb c2 [2] e7 ed }

  condition:
    any of them
}