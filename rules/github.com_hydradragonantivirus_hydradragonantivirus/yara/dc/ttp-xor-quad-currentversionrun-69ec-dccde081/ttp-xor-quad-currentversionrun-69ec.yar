rule TTP_XOR_QUAD_CurrentVersionRun_69ec {
  strings:
    $key_69ec = { 3a 83 [2] 1e 8d [2] 35 a1 [2] 1b 83 [2] 0f 98 [2] 00 82 [2] 1e 9f [2] 1c 9e [2] 07 98 [2] 1b 9f [2] 07 b0 }

  condition:
    any of them
}