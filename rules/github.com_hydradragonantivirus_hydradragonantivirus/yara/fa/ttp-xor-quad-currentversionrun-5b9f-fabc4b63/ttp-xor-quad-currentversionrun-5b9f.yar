rule TTP_XOR_QUAD_CurrentVersionRun_5b9f {
  strings:
    $key_5b9f = { 08 f0 [2] 2c fe [2] 07 d2 [2] 29 f0 [2] 3d eb [2] 32 f1 [2] 2c ec [2] 2e ed [2] 35 eb [2] 29 ec [2] 35 c3 }

  condition:
    any of them
}