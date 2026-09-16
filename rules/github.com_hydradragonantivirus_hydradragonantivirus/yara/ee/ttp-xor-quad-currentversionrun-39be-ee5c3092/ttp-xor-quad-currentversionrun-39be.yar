rule TTP_XOR_QUAD_CurrentVersionRun_39be {
  strings:
    $key_39be = { 6a d1 [2] 4e df [2] 65 f3 [2] 4b d1 [2] 5f ca [2] 50 d0 [2] 4e cd [2] 4c cc [2] 57 ca [2] 4b cd [2] 57 e2 }

  condition:
    any of them
}