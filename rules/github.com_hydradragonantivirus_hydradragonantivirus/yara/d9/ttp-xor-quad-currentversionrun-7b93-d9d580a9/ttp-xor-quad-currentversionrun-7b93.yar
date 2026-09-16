rule TTP_XOR_QUAD_CurrentVersionRun_7b93 {
  strings:
    $key_7b93 = { 28 fc [2] 0c f2 [2] 27 de [2] 09 fc [2] 1d e7 [2] 12 fd [2] 0c e0 [2] 0e e1 [2] 15 e7 [2] 09 e0 [2] 15 cf }

  condition:
    any of them
}