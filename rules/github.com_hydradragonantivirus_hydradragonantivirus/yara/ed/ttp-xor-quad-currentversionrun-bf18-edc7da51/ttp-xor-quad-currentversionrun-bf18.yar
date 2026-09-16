rule TTP_XOR_QUAD_CurrentVersionRun_bf18 {
  strings:
    $key_bf18 = { ec 77 [2] c8 79 [2] e3 55 [2] cd 77 [2] d9 6c [2] d6 76 [2] c8 6b [2] ca 6a [2] d1 6c [2] cd 6b [2] d1 44 }

  condition:
    any of them
}