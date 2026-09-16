rule TTP_XOR_QUAD_CurrentVersionRun_5333 {
  strings:
    $key_5333 = { 00 5c [2] 24 52 [2] 0f 7e [2] 21 5c [2] 35 47 [2] 3a 5d [2] 24 40 [2] 26 41 [2] 3d 47 [2] 21 40 [2] 3d 6f }

  condition:
    any of them
}