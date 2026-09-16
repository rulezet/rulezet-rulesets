rule TTP_XOR_QUAD_CurrentVersionRun_f393 {
  strings:
    $key_f393 = { a0 fc [2] 84 f2 [2] af de [2] 81 fc [2] 95 e7 [2] 9a fd [2] 84 e0 [2] 86 e1 [2] 9d e7 [2] 81 e0 [2] 9d cf }

  condition:
    any of them
}