rule TTP_XOR_QUAD_CurrentVersionRun_a316 {
  strings:
    $key_a316 = { f0 79 [2] d4 77 [2] ff 5b [2] d1 79 [2] c5 62 [2] ca 78 [2] d4 65 [2] d6 64 [2] cd 62 [2] d1 65 [2] cd 4a }

  condition:
    any of them
}