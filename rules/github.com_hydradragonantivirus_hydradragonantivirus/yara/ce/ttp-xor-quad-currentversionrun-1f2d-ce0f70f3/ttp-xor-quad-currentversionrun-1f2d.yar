rule TTP_XOR_QUAD_CurrentVersionRun_1f2d {
  strings:
    $key_1f2d = { 4c 42 [2] 68 4c [2] 43 60 [2] 6d 42 [2] 79 59 [2] 76 43 [2] 68 5e [2] 6a 5f [2] 71 59 [2] 6d 5e [2] 71 71 }

  condition:
    any of them
}