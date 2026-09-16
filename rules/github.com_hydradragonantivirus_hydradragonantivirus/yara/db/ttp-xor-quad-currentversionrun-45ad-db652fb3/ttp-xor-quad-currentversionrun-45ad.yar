rule TTP_XOR_QUAD_CurrentVersionRun_45ad {
  strings:
    $key_45ad = { 16 c2 [2] 32 cc [2] 19 e0 [2] 37 c2 [2] 23 d9 [2] 2c c3 [2] 32 de [2] 30 df [2] 2b d9 [2] 37 de [2] 2b f1 }

  condition:
    any of them
}