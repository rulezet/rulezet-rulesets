rule TTP_XOR_QUAD_CurrentVersionRun_5f33 {
  strings:
    $key_5f33 = { 0c 5c [2] 28 52 [2] 03 7e [2] 2d 5c [2] 39 47 [2] 36 5d [2] 28 40 [2] 2a 41 [2] 31 47 [2] 2d 40 [2] 31 6f }

  condition:
    any of them
}