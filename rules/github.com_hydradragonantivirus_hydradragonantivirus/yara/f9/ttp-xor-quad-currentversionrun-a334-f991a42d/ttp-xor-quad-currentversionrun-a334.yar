rule TTP_XOR_QUAD_CurrentVersionRun_a334 {
  strings:
    $key_a334 = { f0 5b [2] d4 55 [2] ff 79 [2] d1 5b [2] c5 40 [2] ca 5a [2] d4 47 [2] d6 46 [2] cd 40 [2] d1 47 [2] cd 68 }

  condition:
    any of them
}