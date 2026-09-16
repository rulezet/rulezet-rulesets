rule TTP_XOR_QUAD_CurrentVersionRun_bf33 {
  strings:
    $key_bf33 = { ec 5c [2] c8 52 [2] e3 7e [2] cd 5c [2] d9 47 [2] d6 5d [2] c8 40 [2] ca 41 [2] d1 47 [2] cd 40 [2] d1 6f }

  condition:
    any of them
}