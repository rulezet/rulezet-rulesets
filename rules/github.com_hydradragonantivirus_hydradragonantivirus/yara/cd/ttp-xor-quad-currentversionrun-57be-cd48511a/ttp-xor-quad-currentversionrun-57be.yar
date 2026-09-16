rule TTP_XOR_QUAD_CurrentVersionRun_57be {
  strings:
    $key_57be = { 04 d1 [2] 20 df [2] 0b f3 [2] 25 d1 [2] 31 ca [2] 3e d0 [2] 20 cd [2] 22 cc [2] 39 ca [2] 25 cd [2] 39 e2 }

  condition:
    any of them
}