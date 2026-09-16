rule TTP_XOR_QUAD_CurrentVersionRun_66ec {
  strings:
    $key_66ec = { 35 83 [2] 11 8d [2] 3a a1 [2] 14 83 [2] 00 98 [2] 0f 82 [2] 11 9f [2] 13 9e [2] 08 98 [2] 14 9f [2] 08 b0 }

  condition:
    any of them
}