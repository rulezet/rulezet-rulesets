rule TTP_XOR_QUAD_CurrentVersionRun_a1be {
  strings:
    $key_a1be = { f2 d1 [2] d6 df [2] fd f3 [2] d3 d1 [2] c7 ca [2] c8 d0 [2] d6 cd [2] d4 cc [2] cf ca [2] d3 cd [2] cf e2 }

  condition:
    any of them
}