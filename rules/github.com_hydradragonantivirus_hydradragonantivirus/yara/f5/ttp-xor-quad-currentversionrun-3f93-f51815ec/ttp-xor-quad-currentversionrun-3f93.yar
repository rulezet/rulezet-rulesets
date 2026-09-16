rule TTP_XOR_QUAD_CurrentVersionRun_3f93 {
  strings:
    $key_3f93 = { 6c fc [2] 48 f2 [2] 63 de [2] 4d fc [2] 59 e7 [2] 56 fd [2] 48 e0 [2] 4a e1 [2] 51 e7 [2] 4d e0 [2] 51 cf }

  condition:
    any of them
}