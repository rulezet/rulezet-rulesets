rule TTP_XOR_QUAD_CurrentVersionRun_a324 {
  strings:
    $key_a324 = { f0 4b [2] d4 45 [2] ff 69 [2] d1 4b [2] c5 50 [2] ca 4a [2] d4 57 [2] d6 56 [2] cd 50 [2] d1 57 [2] cd 78 }

  condition:
    any of them
}