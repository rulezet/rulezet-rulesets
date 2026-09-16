rule TTP_XOR_QUAD_CurrentVersionRun_6e4a {
  strings:
    $key_6e4a = { 3d 25 [2] 19 2b [2] 32 07 [2] 1c 25 [2] 08 3e [2] 07 24 [2] 19 39 [2] 1b 38 [2] 00 3e [2] 1c 39 [2] 00 16 }

  condition:
    any of them
}