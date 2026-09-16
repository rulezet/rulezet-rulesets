rule TTP_XOR_QUAD_CurrentVersionRun_bf5b {
  strings:
    $key_bf5b = { ec 34 [2] c8 3a [2] e3 16 [2] cd 34 [2] d9 2f [2] d6 35 [2] c8 28 [2] ca 29 [2] d1 2f [2] cd 28 [2] d1 07 }

  condition:
    any of them
}