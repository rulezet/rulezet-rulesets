rule TTP_XOR_QUAD_CurrentVersionRun_bf58 {
  strings:
    $key_bf58 = { ec 37 [2] c8 39 [2] e3 15 [2] cd 37 [2] d9 2c [2] d6 36 [2] c8 2b [2] ca 2a [2] d1 2c [2] cd 2b [2] d1 04 }

  condition:
    any of them
}