rule TTP_XOR_QUAD_CurrentVersionRun_bffc {
  strings:
    $key_bffc = { ec 93 [2] c8 9d [2] e3 b1 [2] cd 93 [2] d9 88 [2] d6 92 [2] c8 8f [2] ca 8e [2] d1 88 [2] cd 8f [2] d1 a0 }

  condition:
    any of them
}