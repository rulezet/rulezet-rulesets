rule TTP_XOR_QUAD_CurrentVersionRun_bf47 {
  strings:
    $key_bf47 = { ec 28 [2] c8 26 [2] e3 0a [2] cd 28 [2] d9 33 [2] d6 29 [2] c8 34 [2] ca 35 [2] d1 33 [2] cd 34 [2] d1 1b }

  condition:
    any of them
}