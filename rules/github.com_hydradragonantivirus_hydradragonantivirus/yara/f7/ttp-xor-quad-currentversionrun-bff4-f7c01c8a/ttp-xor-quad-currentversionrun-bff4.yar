rule TTP_XOR_QUAD_CurrentVersionRun_bff4 {
  strings:
    $key_bff4 = { ec 9b [2] c8 95 [2] e3 b9 [2] cd 9b [2] d9 80 [2] d6 9a [2] c8 87 [2] ca 86 [2] d1 80 [2] cd 87 [2] d1 a8 }

  condition:
    any of them
}