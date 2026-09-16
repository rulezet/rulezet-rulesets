rule TTP_XOR_QUAD_CurrentVersionRun_a402 {
  strings:
    $key_a402 = { f7 6d [2] d3 63 [2] f8 4f [2] d6 6d [2] c2 76 [2] cd 6c [2] d3 71 [2] d1 70 [2] ca 76 [2] d6 71 [2] ca 5e }

  condition:
    any of them
}