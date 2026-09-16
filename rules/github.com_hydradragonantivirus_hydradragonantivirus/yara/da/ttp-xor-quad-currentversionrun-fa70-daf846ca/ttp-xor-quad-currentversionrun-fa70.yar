rule TTP_XOR_QUAD_CurrentVersionRun_fa70 {
  strings:
    $key_fa70 = { a9 1f [2] 8d 11 [2] a6 3d [2] 88 1f [2] 9c 04 [2] 93 1e [2] 8d 03 [2] 8f 02 [2] 94 04 [2] 88 03 [2] 94 2c }

  condition:
    any of them
}