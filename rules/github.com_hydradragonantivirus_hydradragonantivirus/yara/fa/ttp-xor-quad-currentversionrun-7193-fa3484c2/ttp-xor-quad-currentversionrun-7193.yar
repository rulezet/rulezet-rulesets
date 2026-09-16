rule TTP_XOR_QUAD_CurrentVersionRun_7193 {
  strings:
    $key_7193 = { 22 fc [2] 06 f2 [2] 2d de [2] 03 fc [2] 17 e7 [2] 18 fd [2] 06 e0 [2] 04 e1 [2] 1f e7 [2] 03 e0 [2] 1f cf }

  condition:
    any of them
}