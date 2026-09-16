rule TTP_XOR_QUAD_CurrentVersionRun_a335 {
  strings:
    $key_a335 = { f0 5a [2] d4 54 [2] ff 78 [2] d1 5a [2] c5 41 [2] ca 5b [2] d4 46 [2] d6 47 [2] cd 41 [2] d1 46 [2] cd 69 }

  condition:
    any of them
}