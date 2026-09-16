rule TTP_XOR_QUAD_CurrentVersionRun_bf5e {
  strings:
    $key_bf5e = { ec 31 [2] c8 3f [2] e3 13 [2] cd 31 [2] d9 2a [2] d6 30 [2] c8 2d [2] ca 2c [2] d1 2a [2] cd 2d [2] d1 02 }

  condition:
    any of them
}