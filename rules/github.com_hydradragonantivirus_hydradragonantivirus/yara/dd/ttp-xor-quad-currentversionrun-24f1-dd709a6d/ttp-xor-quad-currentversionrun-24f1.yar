rule TTP_XOR_QUAD_CurrentVersionRun_24f1 {
  strings:
    $key_24f1 = { 77 9e [2] 53 90 [2] 78 bc [2] 56 9e [2] 42 85 [2] 4d 9f [2] 53 82 [2] 51 83 [2] 4a 85 [2] 56 82 [2] 4a ad }

  condition:
    any of them
}