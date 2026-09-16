rule TTP_XOR_QUAD_CurrentVersionRun_3b00 {
  strings:
    $key_3b00 = { 68 6f [2] 4c 61 [2] 67 4d [2] 49 6f [2] 5d 74 [2] 52 6e [2] 4c 73 [2] 4e 72 [2] 55 74 [2] 49 73 [2] 55 5c }

  condition:
    any of them
}