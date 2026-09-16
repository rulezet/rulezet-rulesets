rule TTP_XOR_QUAD_CurrentVersionRun_bf40 {
  strings:
    $key_bf40 = { ec 2f [2] c8 21 [2] e3 0d [2] cd 2f [2] d9 34 [2] d6 2e [2] c8 33 [2] ca 32 [2] d1 34 [2] cd 33 [2] d1 1c }

  condition:
    any of them
}