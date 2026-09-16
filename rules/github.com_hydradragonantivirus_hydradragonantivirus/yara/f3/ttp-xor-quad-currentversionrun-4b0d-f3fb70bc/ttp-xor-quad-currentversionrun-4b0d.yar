rule TTP_XOR_QUAD_CurrentVersionRun_4b0d {
  strings:
    $key_4b0d = { 18 62 [2] 3c 6c [2] 17 40 [2] 39 62 [2] 2d 79 [2] 22 63 [2] 3c 7e [2] 3e 7f [2] 25 79 [2] 39 7e [2] 25 51 }

  condition:
    any of them
}