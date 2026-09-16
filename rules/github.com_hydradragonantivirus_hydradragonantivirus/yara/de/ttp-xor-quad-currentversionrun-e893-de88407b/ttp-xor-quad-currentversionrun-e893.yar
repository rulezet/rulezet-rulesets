rule TTP_XOR_QUAD_CurrentVersionRun_e893 {
  strings:
    $key_e893 = { bb fc [2] 9f f2 [2] b4 de [2] 9a fc [2] 8e e7 [2] 81 fd [2] 9f e0 [2] 9d e1 [2] 86 e7 [2] 9a e0 [2] 86 cf }

  condition:
    any of them
}