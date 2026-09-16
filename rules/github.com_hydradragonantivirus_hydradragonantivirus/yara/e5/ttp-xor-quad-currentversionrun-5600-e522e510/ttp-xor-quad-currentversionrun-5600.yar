rule TTP_XOR_QUAD_CurrentVersionRun_5600 {
  strings:
    $key_5600 = { 05 6f [2] 21 61 [2] 0a 4d [2] 24 6f [2] 30 74 [2] 3f 6e [2] 21 73 [2] 23 72 [2] 38 74 [2] 24 73 [2] 38 5c }

  condition:
    any of them
}