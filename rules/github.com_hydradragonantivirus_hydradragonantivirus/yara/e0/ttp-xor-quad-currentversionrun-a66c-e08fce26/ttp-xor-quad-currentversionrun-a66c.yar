rule TTP_XOR_QUAD_CurrentVersionRun_a66c {
  strings:
    $key_a66c = { f5 03 [2] d1 0d [2] fa 21 [2] d4 03 [2] c0 18 [2] cf 02 [2] d1 1f [2] d3 1e [2] c8 18 [2] d4 1f [2] c8 30 }

  condition:
    any of them
}