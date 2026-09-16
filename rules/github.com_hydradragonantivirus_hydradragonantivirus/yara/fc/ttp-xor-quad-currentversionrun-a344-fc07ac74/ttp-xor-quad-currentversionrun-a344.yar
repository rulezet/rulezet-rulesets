rule TTP_XOR_QUAD_CurrentVersionRun_a344 {
  strings:
    $key_a344 = { f0 2b [2] d4 25 [2] ff 09 [2] d1 2b [2] c5 30 [2] ca 2a [2] d4 37 [2] d6 36 [2] cd 30 [2] d1 37 [2] cd 18 }

  condition:
    any of them
}