rule TTP_XOR_QUAD_CurrentVersionRun_bfeb {
  strings:
    $key_bfeb = { ec 84 [2] c8 8a [2] e3 a6 [2] cd 84 [2] d9 9f [2] d6 85 [2] c8 98 [2] ca 99 [2] d1 9f [2] cd 98 [2] d1 b7 }

  condition:
    any of them
}