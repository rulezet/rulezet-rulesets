rule TTP_XOR_QUAD_CurrentVersionRun_bf0d {
  strings:
    $key_bf0d = { ec 62 [2] c8 6c [2] e3 40 [2] cd 62 [2] d9 79 [2] d6 63 [2] c8 7e [2] ca 7f [2] d1 79 [2] cd 7e [2] d1 51 }

  condition:
    any of them
}