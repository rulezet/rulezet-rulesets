rule TTP_XOR_QUAD_CurrentVersionRun_f9b1 {
  strings:
    $key_f9b1 = { aa de [2] 8e d0 [2] a5 fc [2] 8b de [2] 9f c5 [2] 90 df [2] 8e c2 [2] 8c c3 [2] 97 c5 [2] 8b c2 [2] 97 ed }

  condition:
    any of them
}