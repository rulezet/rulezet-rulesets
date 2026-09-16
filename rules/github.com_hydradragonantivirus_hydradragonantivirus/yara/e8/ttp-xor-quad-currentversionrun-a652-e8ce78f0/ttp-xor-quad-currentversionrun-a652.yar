rule TTP_XOR_QUAD_CurrentVersionRun_a652 {
  strings:
    $key_a652 = { f5 3d [2] d1 33 [2] fa 1f [2] d4 3d [2] c0 26 [2] cf 3c [2] d1 21 [2] d3 20 [2] c8 26 [2] d4 21 [2] c8 0e }

  condition:
    any of them
}