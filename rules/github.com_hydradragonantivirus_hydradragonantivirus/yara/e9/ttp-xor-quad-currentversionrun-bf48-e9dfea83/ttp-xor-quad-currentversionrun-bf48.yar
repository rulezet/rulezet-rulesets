rule TTP_XOR_QUAD_CurrentVersionRun_bf48 {
  strings:
    $key_bf48 = { ec 27 [2] c8 29 [2] e3 05 [2] cd 27 [2] d9 3c [2] d6 26 [2] c8 3b [2] ca 3a [2] d1 3c [2] cd 3b [2] d1 14 }

  condition:
    any of them
}