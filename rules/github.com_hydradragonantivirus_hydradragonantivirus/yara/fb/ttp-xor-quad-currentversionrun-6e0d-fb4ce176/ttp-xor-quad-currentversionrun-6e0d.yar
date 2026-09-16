rule TTP_XOR_QUAD_CurrentVersionRun_6e0d {
  strings:
    $key_6e0d = { 3d 62 [2] 19 6c [2] 32 40 [2] 1c 62 [2] 08 79 [2] 07 63 [2] 19 7e [2] 1b 7f [2] 00 79 [2] 1c 7e [2] 00 51 }

  condition:
    any of them
}