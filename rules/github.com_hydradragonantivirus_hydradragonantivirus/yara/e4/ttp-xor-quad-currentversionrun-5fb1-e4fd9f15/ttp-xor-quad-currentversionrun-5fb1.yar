rule TTP_XOR_QUAD_CurrentVersionRun_5fb1 {
  strings:
    $key_5fb1 = { 0c de [2] 28 d0 [2] 03 fc [2] 2d de [2] 39 c5 [2] 36 df [2] 28 c2 [2] 2a c3 [2] 31 c5 [2] 2d c2 [2] 31 ed }

  condition:
    any of them
}