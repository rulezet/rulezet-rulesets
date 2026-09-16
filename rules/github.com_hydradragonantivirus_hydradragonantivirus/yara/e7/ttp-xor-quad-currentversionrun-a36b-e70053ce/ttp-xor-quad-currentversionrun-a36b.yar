rule TTP_XOR_QUAD_CurrentVersionRun_a36b {
  strings:
    $key_a36b = { f0 04 [2] d4 0a [2] ff 26 [2] d1 04 [2] c5 1f [2] ca 05 [2] d4 18 [2] d6 19 [2] cd 1f [2] d1 18 [2] cd 37 }

  condition:
    any of them
}