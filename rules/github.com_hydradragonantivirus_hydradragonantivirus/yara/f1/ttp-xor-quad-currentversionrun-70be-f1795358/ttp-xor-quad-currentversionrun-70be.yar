rule TTP_XOR_QUAD_CurrentVersionRun_70be {
  strings:
    $key_70be = { 23 d1 [2] 07 df [2] 2c f3 [2] 02 d1 [2] 16 ca [2] 19 d0 [2] 07 cd [2] 05 cc [2] 1e ca [2] 02 cd [2] 1e e2 }

  condition:
    any of them
}