rule TTP_XOR_QUAD_CurrentVersionRun_5330 {
  strings:
    $key_5330 = { 00 5f [2] 24 51 [2] 0f 7d [2] 21 5f [2] 35 44 [2] 3a 5e [2] 24 43 [2] 26 42 [2] 3d 44 [2] 21 43 [2] 3d 6c }

  condition:
    any of them
}