rule TTP_XOR_QUAD_CurrentVersionRun_64f1 {
  strings:
    $key_64f1 = { 37 9e [2] 13 90 [2] 38 bc [2] 16 9e [2] 02 85 [2] 0d 9f [2] 13 82 [2] 11 83 [2] 0a 85 [2] 16 82 [2] 0a ad }

  condition:
    any of them
}