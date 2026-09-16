rule TTP_XOR_QUAD_CurrentVersionRun_6110 {
  strings:
    $key_6110 = { 32 7f [2] 16 71 [2] 3d 5d [2] 13 7f [2] 07 64 [2] 08 7e [2] 16 63 [2] 14 62 [2] 0f 64 [2] 13 63 [2] 0f 4c }

  condition:
    any of them
}