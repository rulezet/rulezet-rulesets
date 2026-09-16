rule TTP_XOR_QUAD_CurrentVersionRun_bdc1 {
  strings:
    $key_bdc1 = { ee ae [2] ca a0 [2] e1 8c [2] cf ae [2] db b5 [2] d4 af [2] ca b2 [2] c8 b3 [2] d3 b5 [2] cf b2 [2] d3 9d }

  condition:
    any of them
}