rule TTP_XOR_QUAD_CurrentVersionRun_409d {
  strings:
    $key_409d = { 13 f2 [2] 37 fc [2] 1c d0 [2] 32 f2 [2] 26 e9 [2] 29 f3 [2] 37 ee [2] 35 ef [2] 2e e9 [2] 32 ee [2] 2e c1 }

  condition:
    any of them
}