rule TTP_XOR_QUAD_CurrentVersionRun_a32d {
  strings:
    $key_a32d = { f0 42 [2] d4 4c [2] ff 60 [2] d1 42 [2] c5 59 [2] ca 43 [2] d4 5e [2] d6 5f [2] cd 59 [2] d1 5e [2] cd 71 }

  condition:
    any of them
}