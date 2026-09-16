rule TTP_XOR_QUAD_CurrentVersionRun_e0be {
  strings:
    $key_e0be = { b3 d1 [2] 97 df [2] bc f3 [2] 92 d1 [2] 86 ca [2] 89 d0 [2] 97 cd [2] 95 cc [2] 8e ca [2] 92 cd [2] 8e e2 }

  condition:
    any of them
}