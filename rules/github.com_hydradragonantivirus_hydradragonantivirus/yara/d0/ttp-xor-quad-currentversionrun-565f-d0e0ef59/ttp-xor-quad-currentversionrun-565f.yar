rule TTP_XOR_QUAD_CurrentVersionRun_565f {
  strings:
    $key_565f = { 05 30 [2] 21 3e [2] 0a 12 [2] 24 30 [2] 30 2b [2] 3f 31 [2] 21 2c [2] 23 2d [2] 38 2b [2] 24 2c [2] 38 03 }

  condition:
    any of them
}