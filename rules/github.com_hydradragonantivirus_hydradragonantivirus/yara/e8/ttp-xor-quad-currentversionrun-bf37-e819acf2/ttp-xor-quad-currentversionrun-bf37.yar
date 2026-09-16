rule TTP_XOR_QUAD_CurrentVersionRun_bf37 {
  strings:
    $key_bf37 = { ec 58 [2] c8 56 [2] e3 7a [2] cd 58 [2] d9 43 [2] d6 59 [2] c8 44 [2] ca 45 [2] d1 43 [2] cd 44 [2] d1 6b }

  condition:
    any of them
}