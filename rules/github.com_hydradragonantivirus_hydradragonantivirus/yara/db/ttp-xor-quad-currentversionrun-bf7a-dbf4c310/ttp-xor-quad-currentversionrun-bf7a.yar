rule TTP_XOR_QUAD_CurrentVersionRun_bf7a {
  strings:
    $key_bf7a = { ec 15 [2] c8 1b [2] e3 37 [2] cd 15 [2] d9 0e [2] d6 14 [2] c8 09 [2] ca 08 [2] d1 0e [2] cd 09 [2] d1 26 }

  condition:
    any of them
}