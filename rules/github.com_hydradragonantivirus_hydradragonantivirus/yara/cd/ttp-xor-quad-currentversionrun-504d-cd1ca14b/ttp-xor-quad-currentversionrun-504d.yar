rule TTP_XOR_QUAD_CurrentVersionRun_504d {
  strings:
    $key_504d = { 03 22 [2] 27 2c [2] 0c 00 [2] 22 22 [2] 36 39 [2] 39 23 [2] 27 3e [2] 25 3f [2] 3e 39 [2] 22 3e [2] 3e 11 }

  condition:
    any of them
}