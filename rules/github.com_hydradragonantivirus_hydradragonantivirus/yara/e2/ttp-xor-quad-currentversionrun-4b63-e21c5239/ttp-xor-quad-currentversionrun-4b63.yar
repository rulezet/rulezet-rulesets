rule TTP_XOR_QUAD_CurrentVersionRun_4b63 {
  strings:
    $key_4b63 = { 18 0c [2] 3c 02 [2] 17 2e [2] 39 0c [2] 2d 17 [2] 22 0d [2] 3c 10 [2] 3e 11 [2] 25 17 [2] 39 10 [2] 25 3f }

  condition:
    any of them
}