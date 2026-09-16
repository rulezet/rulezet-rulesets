rule TTP_XOR_QUAD_CurrentVersionRun_536f {
  strings:
    $key_536f = { 00 00 [2] 24 0e [2] 0f 22 [2] 21 00 [2] 35 1b [2] 3a 01 [2] 24 1c [2] 26 1d [2] 3d 1b [2] 21 1c [2] 3d 33 }

  condition:
    any of them
}