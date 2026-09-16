rule TTP_XOR_QUAD_CurrentVersionRun_5693 {
  strings:
    $key_5693 = { 05 fc [2] 21 f2 [2] 0a de [2] 24 fc [2] 30 e7 [2] 3f fd [2] 21 e0 [2] 23 e1 [2] 38 e7 [2] 24 e0 [2] 38 cf }

  condition:
    any of them
}