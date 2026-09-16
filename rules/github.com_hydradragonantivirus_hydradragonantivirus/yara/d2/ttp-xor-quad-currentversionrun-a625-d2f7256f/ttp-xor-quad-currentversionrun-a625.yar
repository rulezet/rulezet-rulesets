rule TTP_XOR_QUAD_CurrentVersionRun_a625 {
  strings:
    $key_a625 = { f5 4a [2] d1 44 [2] fa 68 [2] d4 4a [2] c0 51 [2] cf 4b [2] d1 56 [2] d3 57 [2] c8 51 [2] d4 56 [2] c8 79 }

  condition:
    any of them
}