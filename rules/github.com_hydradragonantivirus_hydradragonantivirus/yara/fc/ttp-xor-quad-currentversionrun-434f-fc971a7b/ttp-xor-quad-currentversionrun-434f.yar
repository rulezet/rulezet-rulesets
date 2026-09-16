rule TTP_XOR_QUAD_CurrentVersionRun_434f {
  strings:
    $key_434f = { 10 20 [2] 34 2e [2] 1f 02 [2] 31 20 [2] 25 3b [2] 2a 21 [2] 34 3c [2] 36 3d [2] 2d 3b [2] 31 3c [2] 2d 13 }

  condition:
    any of them
}