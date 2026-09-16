rule TTP_XOR_QUAD_CurrentVersionRun_bfac {
  strings:
    $key_bfac = { ec c3 [2] c8 cd [2] e3 e1 [2] cd c3 [2] d9 d8 [2] d6 c2 [2] c8 df [2] ca de [2] d1 d8 [2] cd df [2] d1 f0 }

  condition:
    any of them
}