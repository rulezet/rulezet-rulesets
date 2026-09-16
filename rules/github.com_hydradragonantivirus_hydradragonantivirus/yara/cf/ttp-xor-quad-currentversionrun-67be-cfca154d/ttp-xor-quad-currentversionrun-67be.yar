rule TTP_XOR_QUAD_CurrentVersionRun_67be {
  strings:
    $key_67be = { 34 d1 [2] 10 df [2] 3b f3 [2] 15 d1 [2] 01 ca [2] 0e d0 [2] 10 cd [2] 12 cc [2] 09 ca [2] 15 cd [2] 09 e2 }

  condition:
    any of them
}