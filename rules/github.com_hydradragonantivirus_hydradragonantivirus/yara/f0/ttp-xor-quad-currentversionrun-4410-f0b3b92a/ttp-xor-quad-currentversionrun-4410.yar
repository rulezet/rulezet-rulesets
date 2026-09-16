rule TTP_XOR_QUAD_CurrentVersionRun_4410 {
  strings:
    $key_4410 = { 17 7f [2] 33 71 [2] 18 5d [2] 36 7f [2] 22 64 [2] 2d 7e [2] 33 63 [2] 31 62 [2] 2a 64 [2] 36 63 [2] 2a 4c }

  condition:
    any of them
}