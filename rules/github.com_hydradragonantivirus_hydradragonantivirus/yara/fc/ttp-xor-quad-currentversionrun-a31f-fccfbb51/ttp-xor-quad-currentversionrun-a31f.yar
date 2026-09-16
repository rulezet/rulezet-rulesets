rule TTP_XOR_QUAD_CurrentVersionRun_a31f {
  strings:
    $key_a31f = { f0 70 [2] d4 7e [2] ff 52 [2] d1 70 [2] c5 6b [2] ca 71 [2] d4 6c [2] d6 6d [2] cd 6b [2] d1 6c [2] cd 43 }

  condition:
    any of them
}