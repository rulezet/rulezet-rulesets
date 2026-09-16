rule TTP_XOR_QUAD_CurrentVersionRun_6e4c {
  strings:
    $key_6e4c = { 3d 23 [2] 19 2d [2] 32 01 [2] 1c 23 [2] 08 38 [2] 07 22 [2] 19 3f [2] 1b 3e [2] 00 38 [2] 1c 3f [2] 00 10 }

  condition:
    any of them
}