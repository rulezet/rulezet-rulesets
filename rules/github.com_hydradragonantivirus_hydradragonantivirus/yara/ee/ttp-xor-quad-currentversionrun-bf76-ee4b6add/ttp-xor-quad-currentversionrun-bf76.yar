rule TTP_XOR_QUAD_CurrentVersionRun_bf76 {
  strings:
    $key_bf76 = { ec 19 [2] c8 17 [2] e3 3b [2] cd 19 [2] d9 02 [2] d6 18 [2] c8 05 [2] ca 04 [2] d1 02 [2] cd 05 [2] d1 2a }

  condition:
    any of them
}