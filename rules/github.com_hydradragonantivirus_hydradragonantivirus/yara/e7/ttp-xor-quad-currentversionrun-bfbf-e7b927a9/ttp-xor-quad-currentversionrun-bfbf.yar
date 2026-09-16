rule TTP_XOR_QUAD_CurrentVersionRun_bfbf {
  strings:
    $key_bfbf = { ec d0 [2] c8 de [2] e3 f2 [2] cd d0 [2] d9 cb [2] d6 d1 [2] c8 cc [2] ca cd [2] d1 cb [2] cd cc [2] d1 e3 }

  condition:
    any of them
}