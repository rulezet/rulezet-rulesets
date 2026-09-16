rule TTP_XOR_QUAD_CurrentVersionRun_bfe9 {
  strings:
    $key_bfe9 = { ec 86 [2] c8 88 [2] e3 a4 [2] cd 86 [2] d9 9d [2] d6 87 [2] c8 9a [2] ca 9b [2] d1 9d [2] cd 9a [2] d1 b5 }

  condition:
    any of them
}