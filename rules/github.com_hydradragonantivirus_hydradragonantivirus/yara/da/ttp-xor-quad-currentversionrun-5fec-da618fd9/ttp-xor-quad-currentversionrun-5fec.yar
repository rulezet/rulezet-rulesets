rule TTP_XOR_QUAD_CurrentVersionRun_5fec {
  strings:
    $key_5fec = { 0c 83 [2] 28 8d [2] 03 a1 [2] 2d 83 [2] 39 98 [2] 36 82 [2] 28 9f [2] 2a 9e [2] 31 98 [2] 2d 9f [2] 31 b0 }

  condition:
    any of them
}