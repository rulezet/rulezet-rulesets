rule TTP_XOR_QUAD_CurrentVersionRun_67ec {
  strings:
    $key_67ec = { 34 83 [2] 10 8d [2] 3b a1 [2] 15 83 [2] 01 98 [2] 0e 82 [2] 10 9f [2] 12 9e [2] 09 98 [2] 15 9f [2] 09 b0 }

  condition:
    any of them
}