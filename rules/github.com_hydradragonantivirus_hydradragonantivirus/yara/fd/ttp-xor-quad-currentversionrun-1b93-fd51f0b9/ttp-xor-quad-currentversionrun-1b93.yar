rule TTP_XOR_QUAD_CurrentVersionRun_1b93 {
  strings:
    $key_1b93 = { 48 fc [2] 6c f2 [2] 47 de [2] 69 fc [2] 7d e7 [2] 72 fd [2] 6c e0 [2] 6e e1 [2] 75 e7 [2] 69 e0 [2] 75 cf }

  condition:
    any of them
}