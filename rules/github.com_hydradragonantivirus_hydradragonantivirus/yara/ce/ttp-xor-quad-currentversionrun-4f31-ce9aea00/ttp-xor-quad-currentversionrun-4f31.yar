rule TTP_XOR_QUAD_CurrentVersionRun_4f31 {
  strings:
    $key_4f31 = { 1c 5e [2] 38 50 [2] 13 7c [2] 3d 5e [2] 29 45 [2] 26 5f [2] 38 42 [2] 3a 43 [2] 21 45 [2] 3d 42 [2] 21 6d }

  condition:
    any of them
}