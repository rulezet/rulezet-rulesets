rule TTP_XOR_QUAD_CurrentVersionRun_67f0 {
  strings:
    $key_67f0 = { 34 9f [2] 10 91 [2] 3b bd [2] 15 9f [2] 01 84 [2] 0e 9e [2] 10 83 [2] 12 82 [2] 09 84 [2] 15 83 [2] 09 ac }

  condition:
    any of them
}