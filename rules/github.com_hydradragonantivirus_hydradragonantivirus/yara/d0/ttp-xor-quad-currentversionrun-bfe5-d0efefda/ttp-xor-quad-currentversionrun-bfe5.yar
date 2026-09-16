rule TTP_XOR_QUAD_CurrentVersionRun_bfe5 {
  strings:
    $key_bfe5 = { ec 8a [2] c8 84 [2] e3 a8 [2] cd 8a [2] d9 91 [2] d6 8b [2] c8 96 [2] ca 97 [2] d1 91 [2] cd 96 [2] d1 b9 }

  condition:
    any of them
}