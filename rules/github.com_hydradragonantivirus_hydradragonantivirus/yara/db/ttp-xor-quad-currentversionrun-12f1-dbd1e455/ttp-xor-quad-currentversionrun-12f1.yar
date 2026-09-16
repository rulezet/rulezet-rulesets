rule TTP_XOR_QUAD_CurrentVersionRun_12f1 {
  strings:
    $key_12f1 = { 41 9e [2] 65 90 [2] 4e bc [2] 60 9e [2] 74 85 [2] 7b 9f [2] 65 82 [2] 67 83 [2] 7c 85 [2] 60 82 [2] 7c ad }

  condition:
    any of them
}