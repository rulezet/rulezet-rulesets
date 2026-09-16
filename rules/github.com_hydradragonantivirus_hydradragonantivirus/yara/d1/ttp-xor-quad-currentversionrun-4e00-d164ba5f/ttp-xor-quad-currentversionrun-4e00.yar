rule TTP_XOR_QUAD_CurrentVersionRun_4e00 {
  strings:
    $key_4e00 = { 1d 6f [2] 39 61 [2] 12 4d [2] 3c 6f [2] 28 74 [2] 27 6e [2] 39 73 [2] 3b 72 [2] 20 74 [2] 3c 73 [2] 20 5c }

  condition:
    any of them
}