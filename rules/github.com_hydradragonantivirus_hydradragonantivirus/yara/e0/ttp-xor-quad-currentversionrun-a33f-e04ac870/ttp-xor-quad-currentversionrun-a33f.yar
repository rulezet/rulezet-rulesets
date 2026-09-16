rule TTP_XOR_QUAD_CurrentVersionRun_a33f {
  strings:
    $key_a33f = { f0 50 [2] d4 5e [2] ff 72 [2] d1 50 [2] c5 4b [2] ca 51 [2] d4 4c [2] d6 4d [2] cd 4b [2] d1 4c [2] cd 63 }

  condition:
    any of them
}