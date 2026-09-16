rule TTP_XOR_QUAD_CurrentVersionRun_bf50 {
  strings:
    $key_bf50 = { ec 3f [2] c8 31 [2] e3 1d [2] cd 3f [2] d9 24 [2] d6 3e [2] c8 23 [2] ca 22 [2] d1 24 [2] cd 23 [2] d1 0c }

  condition:
    any of them
}