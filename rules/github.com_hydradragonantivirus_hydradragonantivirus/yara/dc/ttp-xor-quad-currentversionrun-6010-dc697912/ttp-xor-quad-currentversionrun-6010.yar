rule TTP_XOR_QUAD_CurrentVersionRun_6010 {
  strings:
    $key_6010 = { 33 7f [2] 17 71 [2] 3c 5d [2] 12 7f [2] 06 64 [2] 09 7e [2] 17 63 [2] 15 62 [2] 0e 64 [2] 12 63 [2] 0e 4c }

  condition:
    any of them
}