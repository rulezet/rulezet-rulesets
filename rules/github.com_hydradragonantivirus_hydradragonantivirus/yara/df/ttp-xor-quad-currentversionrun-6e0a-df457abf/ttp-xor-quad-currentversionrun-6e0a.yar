rule TTP_XOR_QUAD_CurrentVersionRun_6e0a {
  strings:
    $key_6e0a = { 3d 65 [2] 19 6b [2] 32 47 [2] 1c 65 [2] 08 7e [2] 07 64 [2] 19 79 [2] 1b 78 [2] 00 7e [2] 1c 79 [2] 00 56 }

  condition:
    any of them
}