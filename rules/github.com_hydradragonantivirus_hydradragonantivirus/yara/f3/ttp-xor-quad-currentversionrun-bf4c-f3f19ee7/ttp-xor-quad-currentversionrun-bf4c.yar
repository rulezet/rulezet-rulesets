rule TTP_XOR_QUAD_CurrentVersionRun_bf4c {
  strings:
    $key_bf4c = { ec 23 [2] c8 2d [2] e3 01 [2] cd 23 [2] d9 38 [2] d6 22 [2] c8 3f [2] ca 3e [2] d1 38 [2] cd 3f [2] d1 10 }

  condition:
    any of them
}