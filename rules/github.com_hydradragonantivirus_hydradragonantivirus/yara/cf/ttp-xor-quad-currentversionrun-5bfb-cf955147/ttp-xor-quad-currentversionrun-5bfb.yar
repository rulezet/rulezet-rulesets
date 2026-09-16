rule TTP_XOR_QUAD_CurrentVersionRun_5bfb {
  strings:
    $key_5bfb = { 08 94 [2] 2c 9a [2] 07 b6 [2] 29 94 [2] 3d 8f [2] 32 95 [2] 2c 88 [2] 2e 89 [2] 35 8f [2] 29 88 [2] 35 a7 }

  condition:
    any of them
}