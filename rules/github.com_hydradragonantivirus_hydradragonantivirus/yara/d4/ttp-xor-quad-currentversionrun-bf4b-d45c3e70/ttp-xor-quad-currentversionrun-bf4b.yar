rule TTP_XOR_QUAD_CurrentVersionRun_bf4b {
  strings:
    $key_bf4b = { ec 24 [2] c8 2a [2] e3 06 [2] cd 24 [2] d9 3f [2] d6 25 [2] c8 38 [2] ca 39 [2] d1 3f [2] cd 38 [2] d1 17 }

  condition:
    any of them
}