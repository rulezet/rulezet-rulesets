rule TTP_XOR_QUAD_CurrentVersionRun_a345 {
  strings:
    $key_a345 = { f0 2a [2] d4 24 [2] ff 08 [2] d1 2a [2] c5 31 [2] ca 2b [2] d4 36 [2] d6 37 [2] cd 31 [2] d1 36 [2] cd 19 }

  condition:
    any of them
}