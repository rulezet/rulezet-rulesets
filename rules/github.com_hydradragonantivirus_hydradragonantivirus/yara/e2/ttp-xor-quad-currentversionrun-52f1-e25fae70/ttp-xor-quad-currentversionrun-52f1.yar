rule TTP_XOR_QUAD_CurrentVersionRun_52f1 {
  strings:
    $key_52f1 = { 01 9e [2] 25 90 [2] 0e bc [2] 20 9e [2] 34 85 [2] 3b 9f [2] 25 82 [2] 27 83 [2] 3c 85 [2] 20 82 [2] 3c ad }

  condition:
    any of them
}