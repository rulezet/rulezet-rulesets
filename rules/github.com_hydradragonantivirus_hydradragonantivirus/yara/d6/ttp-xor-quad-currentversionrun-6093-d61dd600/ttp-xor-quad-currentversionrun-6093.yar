rule TTP_XOR_QUAD_CurrentVersionRun_6093 {
  strings:
    $key_6093 = { 33 fc [2] 17 f2 [2] 3c de [2] 12 fc [2] 06 e7 [2] 09 fd [2] 17 e0 [2] 15 e1 [2] 0e e7 [2] 12 e0 [2] 0e cf }

  condition:
    any of them
}