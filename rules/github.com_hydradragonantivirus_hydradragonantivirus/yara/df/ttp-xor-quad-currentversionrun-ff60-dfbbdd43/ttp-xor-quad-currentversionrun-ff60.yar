rule TTP_XOR_QUAD_CurrentVersionRun_ff60 {
  strings:
    $key_ff60 = { ac 0f [2] 88 01 [2] a3 2d [2] 8d 0f [2] 99 14 [2] 96 0e [2] 88 13 [2] 8a 12 [2] 91 14 [2] 8d 13 [2] 91 3c }

  condition:
    any of them
}