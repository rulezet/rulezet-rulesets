rule TTP_XOR_QUAD_CurrentVersionRun_77be {
  strings:
    $key_77be = { 24 d1 [2] 00 df [2] 2b f3 [2] 05 d1 [2] 11 ca [2] 1e d0 [2] 00 cd [2] 02 cc [2] 19 ca [2] 05 cd [2] 19 e2 }

  condition:
    any of them
}