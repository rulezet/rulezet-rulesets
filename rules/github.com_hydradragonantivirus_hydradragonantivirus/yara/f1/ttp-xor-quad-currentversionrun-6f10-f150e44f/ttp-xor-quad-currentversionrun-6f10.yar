rule TTP_XOR_QUAD_CurrentVersionRun_6f10 {
  strings:
    $key_6f10 = { 3c 7f [2] 18 71 [2] 33 5d [2] 1d 7f [2] 09 64 [2] 06 7e [2] 18 63 [2] 1a 62 [2] 01 64 [2] 1d 63 [2] 01 4c }

  condition:
    any of them
}