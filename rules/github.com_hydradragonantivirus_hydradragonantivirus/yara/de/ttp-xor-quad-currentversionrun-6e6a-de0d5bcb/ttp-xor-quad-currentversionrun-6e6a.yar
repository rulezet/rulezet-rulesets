rule TTP_XOR_QUAD_CurrentVersionRun_6e6a {
  strings:
    $key_6e6a = { 3d 05 [2] 19 0b [2] 32 27 [2] 1c 05 [2] 08 1e [2] 07 04 [2] 19 19 [2] 1b 18 [2] 00 1e [2] 1c 19 [2] 00 36 }

  condition:
    any of them
}