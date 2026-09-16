rule TTP_XOR_QUAD_CurrentVersionRun_bfab {
  strings:
    $key_bfab = { ec c4 [2] c8 ca [2] e3 e6 [2] cd c4 [2] d9 df [2] d6 c5 [2] c8 d8 [2] ca d9 [2] d1 df [2] cd d8 [2] d1 f7 }

  condition:
    any of them
}