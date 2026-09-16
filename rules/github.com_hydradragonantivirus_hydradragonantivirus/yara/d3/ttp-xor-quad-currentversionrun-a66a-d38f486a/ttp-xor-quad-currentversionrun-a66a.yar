rule TTP_XOR_QUAD_CurrentVersionRun_a66a {
  strings:
    $key_a66a = { f5 05 [2] d1 0b [2] fa 27 [2] d4 05 [2] c0 1e [2] cf 04 [2] d1 19 [2] d3 18 [2] c8 1e [2] d4 19 [2] c8 36 }

  condition:
    any of them
}