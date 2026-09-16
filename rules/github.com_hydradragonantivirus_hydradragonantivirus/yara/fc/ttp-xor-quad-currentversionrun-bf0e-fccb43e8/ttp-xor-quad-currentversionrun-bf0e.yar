rule TTP_XOR_QUAD_CurrentVersionRun_bf0e {
  strings:
    $key_bf0e = { ec 61 [2] c8 6f [2] e3 43 [2] cd 61 [2] d9 7a [2] d6 60 [2] c8 7d [2] ca 7c [2] d1 7a [2] cd 7d [2] d1 52 }

  condition:
    any of them
}