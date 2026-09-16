rule TTP_XOR_QUAD_CurrentVersionRun_5810 {
  strings:
    $key_5810 = { 0b 7f [2] 2f 71 [2] 04 5d [2] 2a 7f [2] 3e 64 [2] 31 7e [2] 2f 63 [2] 2d 62 [2] 36 64 [2] 2a 63 [2] 36 4c }

  condition:
    any of them
}