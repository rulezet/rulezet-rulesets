rule TTP_XOR_QUAD_CurrentVersionRun_4f10 {
  strings:
    $key_4f10 = { 1c 7f [2] 38 71 [2] 13 5d [2] 3d 7f [2] 29 64 [2] 26 7e [2] 38 63 [2] 3a 62 [2] 21 64 [2] 3d 63 [2] 21 4c }

  condition:
    any of them
}