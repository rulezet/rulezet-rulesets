rule TTP_XOR_QUAD_CurrentVersionRun_bf7d {
  strings:
    $key_bf7d = { ec 12 [2] c8 1c [2] e3 30 [2] cd 12 [2] d9 09 [2] d6 13 [2] c8 0e [2] ca 0f [2] d1 09 [2] cd 0e [2] d1 21 }

  condition:
    any of them
}