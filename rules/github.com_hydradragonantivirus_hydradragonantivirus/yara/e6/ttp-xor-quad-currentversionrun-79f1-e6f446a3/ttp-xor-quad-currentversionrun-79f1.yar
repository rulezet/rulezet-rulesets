rule TTP_XOR_QUAD_CurrentVersionRun_79f1 {
  strings:
    $key_79f1 = { 2a 9e [2] 0e 90 [2] 25 bc [2] 0b 9e [2] 1f 85 [2] 10 9f [2] 0e 82 [2] 0c 83 [2] 17 85 [2] 0b 82 [2] 17 ad }

  condition:
    any of them
}