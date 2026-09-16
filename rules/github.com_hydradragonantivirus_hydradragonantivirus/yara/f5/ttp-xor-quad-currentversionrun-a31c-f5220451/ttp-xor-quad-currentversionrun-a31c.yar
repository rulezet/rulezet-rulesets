rule TTP_XOR_QUAD_CurrentVersionRun_a31c {
  strings:
    $key_a31c = { f0 73 [2] d4 7d [2] ff 51 [2] d1 73 [2] c5 68 [2] ca 72 [2] d4 6f [2] d6 6e [2] cd 68 [2] d1 6f [2] cd 40 }

  condition:
    any of them
}