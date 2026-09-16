rule TTP_XOR_QUAD_CurrentVersionRun_3393 {
  strings:
    $key_3393 = { 60 fc [2] 44 f2 [2] 6f de [2] 41 fc [2] 55 e7 [2] 5a fd [2] 44 e0 [2] 46 e1 [2] 5d e7 [2] 41 e0 [2] 5d cf }

  condition:
    any of them
}