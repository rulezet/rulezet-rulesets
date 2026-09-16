rule TTP_XOR_QUAD_CurrentVersionRun_611d {
  strings:
    $key_611d = { 32 72 [2] 16 7c [2] 3d 50 [2] 13 72 [2] 07 69 [2] 08 73 [2] 16 6e [2] 14 6f [2] 0f 69 [2] 13 6e [2] 0f 41 }

  condition:
    any of them
}