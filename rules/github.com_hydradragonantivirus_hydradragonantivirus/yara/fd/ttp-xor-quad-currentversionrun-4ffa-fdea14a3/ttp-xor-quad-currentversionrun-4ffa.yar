rule TTP_XOR_QUAD_CurrentVersionRun_4ffa {
  strings:
    $key_4ffa = { 1c 95 [2] 38 9b [2] 13 b7 [2] 3d 95 [2] 29 8e [2] 26 94 [2] 38 89 [2] 3a 88 [2] 21 8e [2] 3d 89 [2] 21 a6 }

  condition:
    any of them
}