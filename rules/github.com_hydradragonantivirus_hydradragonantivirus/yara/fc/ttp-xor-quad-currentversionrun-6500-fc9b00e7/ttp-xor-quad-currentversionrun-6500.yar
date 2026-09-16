rule TTP_XOR_QUAD_CurrentVersionRun_6500 {
  strings:
    $key_6500 = { 36 6f [2] 12 61 [2] 39 4d [2] 17 6f [2] 03 74 [2] 0c 6e [2] 12 73 [2] 10 72 [2] 0b 74 [2] 17 73 [2] 0b 5c }

  condition:
    any of them
}