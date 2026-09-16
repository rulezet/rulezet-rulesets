rule TTP_XOR_QUAD_CurrentVersionRun_bf0b {
  strings:
    $key_bf0b = { ec 64 [2] c8 6a [2] e3 46 [2] cd 64 [2] d9 7f [2] d6 65 [2] c8 78 [2] ca 79 [2] d1 7f [2] cd 78 [2] d1 57 }

  condition:
    any of them
}