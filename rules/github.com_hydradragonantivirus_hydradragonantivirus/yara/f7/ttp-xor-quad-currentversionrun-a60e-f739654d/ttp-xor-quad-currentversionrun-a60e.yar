rule TTP_XOR_QUAD_CurrentVersionRun_a60e {
  strings:
    $key_a60e = { f5 61 [2] d1 6f [2] fa 43 [2] d4 61 [2] c0 7a [2] cf 60 [2] d1 7d [2] d3 7c [2] c8 7a [2] d4 7d [2] c8 52 }

  condition:
    any of them
}