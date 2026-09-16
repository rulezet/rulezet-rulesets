rule TTP_XOR_QUAD_CurrentVersionRun_a34a {
  strings:
    $key_a34a = { f0 25 [2] d4 2b [2] ff 07 [2] d1 25 [2] c5 3e [2] ca 24 [2] d4 39 [2] d6 38 [2] cd 3e [2] d1 39 [2] cd 16 }

  condition:
    any of them
}