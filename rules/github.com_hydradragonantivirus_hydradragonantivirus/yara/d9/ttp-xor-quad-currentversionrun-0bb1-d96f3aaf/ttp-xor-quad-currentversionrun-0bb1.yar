rule TTP_XOR_QUAD_CurrentVersionRun_0bb1 {
  strings:
    $key_0bb1 = { 58 de [2] 7c d0 [2] 57 fc [2] 79 de [2] 6d c5 [2] 62 df [2] 7c c2 [2] 7e c3 [2] 65 c5 [2] 79 c2 [2] 65 ed }

  condition:
    any of them
}