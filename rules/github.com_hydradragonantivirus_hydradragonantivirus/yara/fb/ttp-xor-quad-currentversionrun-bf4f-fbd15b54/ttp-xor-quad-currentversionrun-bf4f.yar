rule TTP_XOR_QUAD_CurrentVersionRun_bf4f {
  strings:
    $key_bf4f = { ec 20 [2] c8 2e [2] e3 02 [2] cd 20 [2] d9 3b [2] d6 21 [2] c8 3c [2] ca 3d [2] d1 3b [2] cd 3c [2] d1 13 }

  condition:
    any of them
}