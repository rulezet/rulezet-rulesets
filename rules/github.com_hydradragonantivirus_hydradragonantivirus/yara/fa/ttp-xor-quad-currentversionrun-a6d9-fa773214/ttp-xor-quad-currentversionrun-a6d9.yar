rule TTP_XOR_QUAD_CurrentVersionRun_a6d9 {
  strings:
    $key_a6d9 = { f5 b6 [2] d1 b8 [2] fa 94 [2] d4 b6 [2] c0 ad [2] cf b7 [2] d1 aa [2] d3 ab [2] c8 ad [2] d4 aa [2] c8 85 }

  condition:
    any of them
}