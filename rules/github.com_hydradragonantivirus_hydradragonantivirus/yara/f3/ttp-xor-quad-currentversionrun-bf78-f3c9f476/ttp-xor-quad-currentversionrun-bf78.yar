rule TTP_XOR_QUAD_CurrentVersionRun_bf78 {
  strings:
    $key_bf78 = { ec 17 [2] c8 19 [2] e3 35 [2] cd 17 [2] d9 0c [2] d6 16 [2] c8 0b [2] ca 0a [2] d1 0c [2] cd 0b [2] d1 24 }

  condition:
    any of them
}