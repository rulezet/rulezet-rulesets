rule TTP_XOR_QUAD_CurrentVersionRun_7eb1 {
  strings:
    $key_7eb1 = { 2d de [2] 09 d0 [2] 22 fc [2] 0c de [2] 18 c5 [2] 17 df [2] 09 c2 [2] 0b c3 [2] 10 c5 [2] 0c c2 [2] 10 ed }

  condition:
    any of them
}