rule TTP_XOR_QUAD_CurrentVersionRun_bf1a {
  strings:
    $key_bf1a = { ec 75 [2] c8 7b [2] e3 57 [2] cd 75 [2] d9 6e [2] d6 74 [2] c8 69 [2] ca 68 [2] d1 6e [2] cd 69 [2] d1 46 }

  condition:
    any of them
}