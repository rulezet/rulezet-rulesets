rule TTP_XOR_QUAD_CurrentVersionRun_bf2c {
  strings:
    $key_bf2c = { ec 43 [2] c8 4d [2] e3 61 [2] cd 43 [2] d9 58 [2] d6 42 [2] c8 5f [2] ca 5e [2] d1 58 [2] cd 5f [2] d1 70 }

  condition:
    any of them
}