rule TTP_XOR_QUAD_CurrentVersionRun_bf25 {
  strings:
    $key_bf25 = { ec 4a [2] c8 44 [2] e3 68 [2] cd 4a [2] d9 51 [2] d6 4b [2] c8 56 [2] ca 57 [2] d1 51 [2] cd 56 [2] d1 79 }

  condition:
    any of them
}