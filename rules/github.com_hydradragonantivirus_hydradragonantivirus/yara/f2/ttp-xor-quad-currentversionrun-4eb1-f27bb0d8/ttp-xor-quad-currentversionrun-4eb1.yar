rule TTP_XOR_QUAD_CurrentVersionRun_4eb1 {
  strings:
    $key_4eb1 = { 1d de [2] 39 d0 [2] 12 fc [2] 3c de [2] 28 c5 [2] 27 df [2] 39 c2 [2] 3b c3 [2] 20 c5 [2] 3c c2 [2] 20 ed }

  condition:
    any of them
}