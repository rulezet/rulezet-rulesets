rule TTP_XOR_QUAD_CurrentVersionRun_5b9d {
  strings:
    $key_5b9d = { 08 f2 [2] 2c fc [2] 07 d0 [2] 29 f2 [2] 3d e9 [2] 32 f3 [2] 2c ee [2] 2e ef [2] 35 e9 [2] 29 ee [2] 35 c1 }

  condition:
    any of them
}