rule TTP_XOR_QUAD_CurrentVersionRun_a368 {
  strings:
    $key_a368 = { f0 07 [2] d4 09 [2] ff 25 [2] d1 07 [2] c5 1c [2] ca 06 [2] d4 1b [2] d6 1a [2] cd 1c [2] d1 1b [2] cd 34 }

  condition:
    any of them
}