rule TTP_XOR_QUAD_CurrentVersionRun_3e81 {
  strings:
    $key_3e81 = { 6d ee [2] 49 e0 [2] 62 cc [2] 4c ee [2] 58 f5 [2] 57 ef [2] 49 f2 [2] 4b f3 [2] 50 f5 [2] 4c f2 [2] 50 dd }

  condition:
    any of them
}