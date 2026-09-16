rule TTP_XOR_QUAD_CurrentVersionRun_e493 {
  strings:
    $key_e493 = { b7 fc [2] 93 f2 [2] b8 de [2] 96 fc [2] 82 e7 [2] 8d fd [2] 93 e0 [2] 91 e1 [2] 8a e7 [2] 96 e0 [2] 8a cf }

  condition:
    any of them
}