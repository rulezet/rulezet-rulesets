rule TTP_XOR_QUAD_CurrentVersionRun_a35d {
  strings:
    $key_a35d = { f0 32 [2] d4 3c [2] ff 10 [2] d1 32 [2] c5 29 [2] ca 33 [2] d4 2e [2] d6 2f [2] cd 29 [2] d1 2e [2] cd 01 }

  condition:
    any of them
}