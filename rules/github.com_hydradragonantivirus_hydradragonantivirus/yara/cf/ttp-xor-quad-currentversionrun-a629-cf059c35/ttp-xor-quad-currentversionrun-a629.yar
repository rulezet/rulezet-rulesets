rule TTP_XOR_QUAD_CurrentVersionRun_a629 {
  strings:
    $key_a629 = { f5 46 [2] d1 48 [2] fa 64 [2] d4 46 [2] c0 5d [2] cf 47 [2] d1 5a [2] d3 5b [2] c8 5d [2] d4 5a [2] c8 75 }

  condition:
    any of them
}