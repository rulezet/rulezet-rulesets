rule TTP_XOR_QUAD_CurrentVersionRun_5bfc {
  strings:
    $key_5bfc = { 08 93 [2] 2c 9d [2] 07 b1 [2] 29 93 [2] 3d 88 [2] 32 92 [2] 2c 8f [2] 2e 8e [2] 35 88 [2] 29 8f [2] 35 a0 }

  condition:
    any of them
}