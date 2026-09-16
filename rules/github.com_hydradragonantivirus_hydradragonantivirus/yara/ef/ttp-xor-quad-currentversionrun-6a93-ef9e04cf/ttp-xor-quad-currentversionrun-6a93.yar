rule TTP_XOR_QUAD_CurrentVersionRun_6a93 {
  strings:
    $key_6a93 = { 39 fc [2] 1d f2 [2] 36 de [2] 18 fc [2] 0c e7 [2] 03 fd [2] 1d e0 [2] 1f e1 [2] 04 e7 [2] 18 e0 [2] 04 cf }

  condition:
    any of them
}