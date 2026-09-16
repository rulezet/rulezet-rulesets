rule TTP_XOR_QUAD_CurrentVersionRun_a30e {
  strings:
    $key_a30e = { f0 61 [2] d4 6f [2] ff 43 [2] d1 61 [2] c5 7a [2] ca 60 [2] d4 7d [2] d6 7c [2] cd 7a [2] d1 7d [2] cd 52 }

  condition:
    any of them
}