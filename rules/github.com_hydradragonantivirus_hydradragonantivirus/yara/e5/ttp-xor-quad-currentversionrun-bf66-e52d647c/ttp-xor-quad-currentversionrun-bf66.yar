rule TTP_XOR_QUAD_CurrentVersionRun_bf66 {
  strings:
    $key_bf66 = { ec 09 [2] c8 07 [2] e3 2b [2] cd 09 [2] d9 12 [2] d6 08 [2] c8 15 [2] ca 14 [2] d1 12 [2] cd 15 [2] d1 3a }

  condition:
    any of them
}