rule TTP_XOR_QUAD_CurrentVersionRun_1093 {
  strings:
    $key_1093 = { 43 fc [2] 67 f2 [2] 4c de [2] 62 fc [2] 76 e7 [2] 79 fd [2] 67 e0 [2] 65 e1 [2] 7e e7 [2] 62 e0 [2] 7e cf }

  condition:
    any of them
}