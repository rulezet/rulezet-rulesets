rule TTP_XOR_QUAD_CurrentVersionRun_4593 {
  strings:
    $key_4593 = { 16 fc [2] 32 f2 [2] 19 de [2] 37 fc [2] 23 e7 [2] 2c fd [2] 32 e0 [2] 30 e1 [2] 2b e7 [2] 37 e0 [2] 2b cf }

  condition:
    any of them
}