rule TTP_XOR_QUAD_CurrentVersionRun_ff93 {
  strings:
    $key_ff93 = { ac fc [2] 88 f2 [2] a3 de [2] 8d fc [2] 99 e7 [2] 96 fd [2] 88 e0 [2] 8a e1 [2] 91 e7 [2] 8d e0 [2] 91 cf }

  condition:
    any of them
}