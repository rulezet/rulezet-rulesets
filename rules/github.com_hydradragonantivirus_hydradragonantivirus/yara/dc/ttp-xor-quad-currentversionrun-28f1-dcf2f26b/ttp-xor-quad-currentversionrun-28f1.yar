rule TTP_XOR_QUAD_CurrentVersionRun_28f1 {
  strings:
    $key_28f1 = { 7b 9e [2] 5f 90 [2] 74 bc [2] 5a 9e [2] 4e 85 [2] 41 9f [2] 5f 82 [2] 5d 83 [2] 46 85 [2] 5a 82 [2] 46 ad }

  condition:
    any of them
}