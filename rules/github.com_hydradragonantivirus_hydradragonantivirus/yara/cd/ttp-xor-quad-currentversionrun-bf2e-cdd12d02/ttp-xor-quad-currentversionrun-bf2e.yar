rule TTP_XOR_QUAD_CurrentVersionRun_bf2e {
  strings:
    $key_bf2e = { ec 41 [2] c8 4f [2] e3 63 [2] cd 41 [2] d9 5a [2] d6 40 [2] c8 5d [2] ca 5c [2] d1 5a [2] cd 5d [2] d1 72 }

  condition:
    any of them
}