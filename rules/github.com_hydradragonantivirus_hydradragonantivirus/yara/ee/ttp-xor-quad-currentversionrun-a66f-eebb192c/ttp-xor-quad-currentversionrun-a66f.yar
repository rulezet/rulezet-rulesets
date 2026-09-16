rule TTP_XOR_QUAD_CurrentVersionRun_a66f {
  strings:
    $key_a66f = { f5 00 [2] d1 0e [2] fa 22 [2] d4 00 [2] c0 1b [2] cf 01 [2] d1 1c [2] d3 1d [2] c8 1b [2] d4 1c [2] c8 33 }

  condition:
    any of them
}