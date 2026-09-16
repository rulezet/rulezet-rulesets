rule TTP_XOR_QUAD_CurrentVersionRun_bffa {
  strings:
    $key_bffa = { ec 95 [2] c8 9b [2] e3 b7 [2] cd 95 [2] d9 8e [2] d6 94 [2] c8 89 [2] ca 88 [2] d1 8e [2] cd 89 [2] d1 a6 }

  condition:
    any of them
}