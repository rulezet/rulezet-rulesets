rule TTP_XOR_QUAD_CurrentVersionRun_a1a3 {
  strings:
    $key_a1a3 = { f2 cc [2] d6 c2 [2] fd ee [2] d3 cc [2] c7 d7 [2] c8 cd [2] d6 d0 [2] d4 d1 [2] cf d7 [2] d3 d0 [2] cf ff }

  condition:
    any of them
}