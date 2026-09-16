rule TTP_XOR_QUAD_CurrentVersionRun_1393 {
  strings:
    $key_1393 = { 40 fc [2] 64 f2 [2] 4f de [2] 61 fc [2] 75 e7 [2] 7a fd [2] 64 e0 [2] 66 e1 [2] 7d e7 [2] 61 e0 [2] 7d cf }

  condition:
    any of them
}