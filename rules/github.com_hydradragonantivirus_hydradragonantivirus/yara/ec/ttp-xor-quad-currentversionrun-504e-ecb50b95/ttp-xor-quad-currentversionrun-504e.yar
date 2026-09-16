rule TTP_XOR_QUAD_CurrentVersionRun_504e {
  strings:
    $key_504e = { 03 21 [2] 27 2f [2] 0c 03 [2] 22 21 [2] 36 3a [2] 39 20 [2] 27 3d [2] 25 3c [2] 3e 3a [2] 22 3d [2] 3e 12 }

  condition:
    any of them
}