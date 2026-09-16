rule TTP_XOR_QUAD_CurrentVersionRun_a4e0 {
  strings:
    $key_a4e0 = { f7 8f [2] d3 81 [2] f8 ad [2] d6 8f [2] c2 94 [2] cd 8e [2] d3 93 [2] d1 92 [2] ca 94 [2] d6 93 [2] ca bc }

  condition:
    any of them
}