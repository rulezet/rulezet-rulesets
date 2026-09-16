rule TTP_XOR_QUAD_CurrentVersionRun_a3ee {
  strings:
    $key_a3ee = { f0 81 [2] d4 8f [2] ff a3 [2] d1 81 [2] c5 9a [2] ca 80 [2] d4 9d [2] d6 9c [2] cd 9a [2] d1 9d [2] cd b2 }

  condition:
    any of them
}