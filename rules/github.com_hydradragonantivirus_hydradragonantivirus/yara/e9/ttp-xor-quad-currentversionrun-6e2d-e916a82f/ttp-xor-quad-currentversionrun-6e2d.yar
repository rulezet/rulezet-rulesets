rule TTP_XOR_QUAD_CurrentVersionRun_6e2d {
  strings:
    $key_6e2d = { 3d 42 [2] 19 4c [2] 32 60 [2] 1c 42 [2] 08 59 [2] 07 43 [2] 19 5e [2] 1b 5f [2] 00 59 [2] 1c 5e [2] 00 71 }

  condition:
    any of them
}