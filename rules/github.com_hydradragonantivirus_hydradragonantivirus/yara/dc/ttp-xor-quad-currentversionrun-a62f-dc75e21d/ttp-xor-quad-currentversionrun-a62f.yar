rule TTP_XOR_QUAD_CurrentVersionRun_a62f {
  strings:
    $key_a62f = { f5 40 [2] d1 4e [2] fa 62 [2] d4 40 [2] c0 5b [2] cf 41 [2] d1 5c [2] d3 5d [2] c8 5b [2] d4 5c [2] c8 73 }

  condition:
    any of them
}