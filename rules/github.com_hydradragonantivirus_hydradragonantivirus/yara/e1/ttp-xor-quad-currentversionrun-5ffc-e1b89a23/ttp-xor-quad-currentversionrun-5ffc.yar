rule TTP_XOR_QUAD_CurrentVersionRun_5ffc {
  strings:
    $key_5ffc = { 0c 93 [2] 28 9d [2] 03 b1 [2] 2d 93 [2] 39 88 [2] 36 92 [2] 28 8f [2] 2a 8e [2] 31 88 [2] 2d 8f [2] 31 a0 }

  condition:
    any of them
}