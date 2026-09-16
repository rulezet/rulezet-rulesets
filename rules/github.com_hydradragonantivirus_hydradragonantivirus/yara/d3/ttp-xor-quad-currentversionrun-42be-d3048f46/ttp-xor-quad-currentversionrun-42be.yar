rule TTP_XOR_QUAD_CurrentVersionRun_42be {
  strings:
    $key_42be = { 11 d1 [2] 35 df [2] 1e f3 [2] 30 d1 [2] 24 ca [2] 2b d0 [2] 35 cd [2] 37 cc [2] 2c ca [2] 30 cd [2] 2c e2 }

  condition:
    any of them
}