rule TTP_XOR_QUAD_CurrentVersionRun_6e20 {
  strings:
    $key_6e20 = { 3d 4f [2] 19 41 [2] 32 6d [2] 1c 4f [2] 08 54 [2] 07 4e [2] 19 53 [2] 1b 52 [2] 00 54 [2] 1c 53 [2] 00 7c }

  condition:
    any of them
}