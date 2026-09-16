rule TTP_XOR_QUAD_CurrentVersionRun_6a60 {
  strings:
    $key_6a60 = { 39 0f [2] 1d 01 [2] 36 2d [2] 18 0f [2] 0c 14 [2] 03 0e [2] 1d 13 [2] 1f 12 [2] 04 14 [2] 18 13 [2] 04 3c }

  condition:
    any of them
}