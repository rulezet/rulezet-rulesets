rule TTP_XOR_QUAD_CurrentVersionRun_63f1 {
  strings:
    $key_63f1 = { 30 9e [2] 14 90 [2] 3f bc [2] 11 9e [2] 05 85 [2] 0a 9f [2] 14 82 [2] 16 83 [2] 0d 85 [2] 11 82 [2] 0d ad }

  condition:
    any of them
}