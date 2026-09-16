rule TTP_XOR_QUAD_CurrentVersionRun_5a10 {
  strings:
    $key_5a10 = { 09 7f [2] 2d 71 [2] 06 5d [2] 28 7f [2] 3c 64 [2] 33 7e [2] 2d 63 [2] 2f 62 [2] 34 64 [2] 28 63 [2] 34 4c }

  condition:
    any of them
}