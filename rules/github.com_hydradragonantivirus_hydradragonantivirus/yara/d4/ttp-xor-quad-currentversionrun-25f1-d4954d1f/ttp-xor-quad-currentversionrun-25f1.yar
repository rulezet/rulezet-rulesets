rule TTP_XOR_QUAD_CurrentVersionRun_25f1 {
  strings:
    $key_25f1 = { 76 9e [2] 52 90 [2] 79 bc [2] 57 9e [2] 43 85 [2] 4c 9f [2] 52 82 [2] 50 83 [2] 4b 85 [2] 57 82 [2] 4b ad }

  condition:
    any of them
}