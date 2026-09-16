rule TTP_XOR_QUAD_CurrentVersionRun_a64f {
  strings:
    $key_a64f = { f5 20 [2] d1 2e [2] fa 02 [2] d4 20 [2] c0 3b [2] cf 21 [2] d1 3c [2] d3 3d [2] c8 3b [2] d4 3c [2] c8 13 }

  condition:
    any of them
}