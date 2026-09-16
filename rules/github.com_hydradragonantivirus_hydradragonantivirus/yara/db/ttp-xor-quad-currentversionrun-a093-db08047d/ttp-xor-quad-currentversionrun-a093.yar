rule TTP_XOR_QUAD_CurrentVersionRun_a093 {
  strings:
    $key_a093 = { f3 fc [2] d7 f2 [2] fc de [2] d2 fc [2] c6 e7 [2] c9 fd [2] d7 e0 [2] d5 e1 [2] ce e7 [2] d2 e0 [2] ce cf }

  condition:
    any of them
}