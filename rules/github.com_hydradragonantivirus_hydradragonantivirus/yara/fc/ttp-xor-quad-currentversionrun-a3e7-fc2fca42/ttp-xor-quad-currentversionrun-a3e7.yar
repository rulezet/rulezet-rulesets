rule TTP_XOR_QUAD_CurrentVersionRun_a3e7 {
  strings:
    $key_a3e7 = { f0 88 [2] d4 86 [2] ff aa [2] d1 88 [2] c5 93 [2] ca 89 [2] d4 94 [2] d6 95 [2] cd 93 [2] d1 94 [2] cd bb }

  condition:
    any of them
}