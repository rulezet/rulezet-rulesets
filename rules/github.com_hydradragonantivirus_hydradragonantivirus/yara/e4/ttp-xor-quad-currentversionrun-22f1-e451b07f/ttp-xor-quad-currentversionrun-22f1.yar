rule TTP_XOR_QUAD_CurrentVersionRun_22f1 {
  strings:
    $key_22f1 = { 71 9e [2] 55 90 [2] 7e bc [2] 50 9e [2] 44 85 [2] 4b 9f [2] 55 82 [2] 57 83 [2] 4c 85 [2] 50 82 [2] 4c ad }

  condition:
    any of them
}