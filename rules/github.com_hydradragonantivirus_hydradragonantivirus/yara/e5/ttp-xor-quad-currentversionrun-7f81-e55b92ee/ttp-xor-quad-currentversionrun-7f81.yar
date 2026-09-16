rule TTP_XOR_QUAD_CurrentVersionRun_7f81 {
  strings:
    $key_7f81 = { 2c ee [2] 08 e0 [2] 23 cc [2] 0d ee [2] 19 f5 [2] 16 ef [2] 08 f2 [2] 0a f3 [2] 11 f5 [2] 0d f2 [2] 11 dd }

  condition:
    any of them
}