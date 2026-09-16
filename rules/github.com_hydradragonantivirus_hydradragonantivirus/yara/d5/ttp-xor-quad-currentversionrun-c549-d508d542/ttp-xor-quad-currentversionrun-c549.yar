rule TTP_XOR_QUAD_CurrentVersionRun_c549 {
  strings:
    $key_c549 = { 96 26 [2] b2 28 [2] 99 04 [2] b7 26 [2] a3 3d [2] ac 27 [2] b2 3a [2] b0 3b [2] ab 3d [2] b7 3a [2] ab 15 }

  condition:
    any of them
}