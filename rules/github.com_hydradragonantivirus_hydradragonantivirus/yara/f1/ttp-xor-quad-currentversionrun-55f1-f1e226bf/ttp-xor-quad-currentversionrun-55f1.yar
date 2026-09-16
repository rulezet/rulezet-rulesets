rule TTP_XOR_QUAD_CurrentVersionRun_55f1 {
  strings:
    $key_55f1 = { 06 9e [2] 22 90 [2] 09 bc [2] 27 9e [2] 33 85 [2] 3c 9f [2] 22 82 [2] 20 83 [2] 3b 85 [2] 27 82 [2] 3b ad }

  condition:
    any of them
}