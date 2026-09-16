rule TTP_XOR_QUAD_CurrentVersionRun_52f0 {
  strings:
    $key_52f0 = { 01 9f [2] 25 91 [2] 0e bd [2] 20 9f [2] 34 84 [2] 3b 9e [2] 25 83 [2] 27 82 [2] 3c 84 [2] 20 83 [2] 3c ac }

  condition:
    any of them
}