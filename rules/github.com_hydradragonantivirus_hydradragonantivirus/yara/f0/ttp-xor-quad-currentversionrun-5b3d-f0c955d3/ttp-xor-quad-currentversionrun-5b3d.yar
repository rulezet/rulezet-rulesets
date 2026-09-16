rule TTP_XOR_QUAD_CurrentVersionRun_5b3d {
  strings:
    $key_5b3d = { 08 52 [2] 2c 5c [2] 07 70 [2] 29 52 [2] 3d 49 [2] 32 53 [2] 2c 4e [2] 2e 4f [2] 35 49 [2] 29 4e [2] 35 61 }

  condition:
    any of them
}