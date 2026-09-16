rule TTP_XOR_QUAD_CurrentVersionRun_6a4c {
  strings:
    $key_6a4c = { 39 23 [2] 1d 2d [2] 36 01 [2] 18 23 [2] 0c 38 [2] 03 22 [2] 1d 3f [2] 1f 3e [2] 04 38 [2] 18 3f [2] 04 10 }

  condition:
    any of them
}