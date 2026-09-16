rule TTP_XOR_QUAD_CurrentVersionRun_bf1b {
  strings:
    $key_bf1b = { ec 74 [2] c8 7a [2] e3 56 [2] cd 74 [2] d9 6f [2] d6 75 [2] c8 68 [2] ca 69 [2] d1 6f [2] cd 68 [2] d1 47 }

  condition:
    any of them
}