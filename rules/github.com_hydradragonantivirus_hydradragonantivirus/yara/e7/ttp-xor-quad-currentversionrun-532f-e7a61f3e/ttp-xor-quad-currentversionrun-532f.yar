rule TTP_XOR_QUAD_CurrentVersionRun_532f {
  strings:
    $key_532f = { 00 40 [2] 24 4e [2] 0f 62 [2] 21 40 [2] 35 5b [2] 3a 41 [2] 24 5c [2] 26 5d [2] 3d 5b [2] 21 5c [2] 3d 73 }

  condition:
    any of them
}