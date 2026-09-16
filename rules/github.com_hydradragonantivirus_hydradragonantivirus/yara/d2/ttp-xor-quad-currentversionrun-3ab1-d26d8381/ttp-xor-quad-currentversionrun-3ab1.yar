rule TTP_XOR_QUAD_CurrentVersionRun_3ab1 {
  strings:
    $key_3ab1 = { 69 de [2] 4d d0 [2] 66 fc [2] 48 de [2] 5c c5 [2] 53 df [2] 4d c2 [2] 4f c3 [2] 54 c5 [2] 48 c2 [2] 54 ed }

  condition:
    any of them
}