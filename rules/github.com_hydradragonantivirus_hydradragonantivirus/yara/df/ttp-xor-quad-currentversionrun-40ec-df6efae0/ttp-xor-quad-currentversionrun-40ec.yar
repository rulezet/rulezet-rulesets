rule TTP_XOR_QUAD_CurrentVersionRun_40ec {
  strings:
    $key_40ec = { 13 83 [2] 37 8d [2] 1c a1 [2] 32 83 [2] 26 98 [2] 29 82 [2] 37 9f [2] 35 9e [2] 2e 98 [2] 32 9f [2] 2e b0 }

  condition:
    any of them
}