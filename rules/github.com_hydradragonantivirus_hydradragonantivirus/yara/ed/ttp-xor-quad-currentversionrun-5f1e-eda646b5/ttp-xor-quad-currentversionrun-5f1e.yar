rule TTP_XOR_QUAD_CurrentVersionRun_5f1e {
  strings:
    $key_5f1e = { 0c 71 [2] 28 7f [2] 03 53 [2] 2d 71 [2] 39 6a [2] 36 70 [2] 28 6d [2] 2a 6c [2] 31 6a [2] 2d 6d [2] 31 42 }

  condition:
    any of them
}