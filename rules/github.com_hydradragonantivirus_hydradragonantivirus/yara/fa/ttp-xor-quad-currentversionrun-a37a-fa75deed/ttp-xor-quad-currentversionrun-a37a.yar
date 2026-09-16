rule TTP_XOR_QUAD_CurrentVersionRun_a37a {
  strings:
    $key_a37a = { f0 15 [2] d4 1b [2] ff 37 [2] d1 15 [2] c5 0e [2] ca 14 [2] d4 09 [2] d6 08 [2] cd 0e [2] d1 09 [2] cd 26 }

  condition:
    any of them
}