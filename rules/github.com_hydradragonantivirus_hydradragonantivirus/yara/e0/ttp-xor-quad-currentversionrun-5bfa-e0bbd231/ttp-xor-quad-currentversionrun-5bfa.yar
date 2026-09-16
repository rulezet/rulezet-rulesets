rule TTP_XOR_QUAD_CurrentVersionRun_5bfa {
  strings:
    $key_5bfa = { 08 95 [2] 2c 9b [2] 07 b7 [2] 29 95 [2] 3d 8e [2] 32 94 [2] 2c 89 [2] 2e 88 [2] 35 8e [2] 29 89 [2] 35 a6 }

  condition:
    any of them
}