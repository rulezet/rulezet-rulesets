rule TTP_XOR_QUAD_CurrentVersionRun_73f1 {
  strings:
    $key_73f1 = { 20 9e [2] 04 90 [2] 2f bc [2] 01 9e [2] 15 85 [2] 1a 9f [2] 04 82 [2] 06 83 [2] 1d 85 [2] 01 82 [2] 1d ad }

  condition:
    any of them
}