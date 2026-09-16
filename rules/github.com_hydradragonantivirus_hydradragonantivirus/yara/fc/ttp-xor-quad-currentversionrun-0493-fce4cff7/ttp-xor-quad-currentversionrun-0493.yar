rule TTP_XOR_QUAD_CurrentVersionRun_0493 {
  strings:
    $key_0493 = { 57 fc [2] 73 f2 [2] 58 de [2] 76 fc [2] 62 e7 [2] 6d fd [2] 73 e0 [2] 71 e1 [2] 6a e7 [2] 76 e0 [2] 6a cf }

  condition:
    any of them
}