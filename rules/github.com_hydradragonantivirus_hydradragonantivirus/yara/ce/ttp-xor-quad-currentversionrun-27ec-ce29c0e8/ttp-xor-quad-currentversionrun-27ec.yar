rule TTP_XOR_QUAD_CurrentVersionRun_27ec {
  strings:
    $key_27ec = { 74 83 [2] 50 8d [2] 7b a1 [2] 55 83 [2] 41 98 [2] 4e 82 [2] 50 9f [2] 52 9e [2] 49 98 [2] 55 9f [2] 49 b0 }

  condition:
    any of them
}