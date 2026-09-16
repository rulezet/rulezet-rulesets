rule TTP_XOR_QUAD_CurrentVersionRun_69be {
  strings:
    $key_69be = { 3a d1 [2] 1e df [2] 35 f3 [2] 1b d1 [2] 0f ca [2] 00 d0 [2] 1e cd [2] 1c cc [2] 07 ca [2] 1b cd [2] 07 e2 }

  condition:
    any of them
}