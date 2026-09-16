rule TTP_XOR_QUAD_CurrentVersionRun_6b00 {
  strings:
    $key_6b00 = { 38 6f [2] 1c 61 [2] 37 4d [2] 19 6f [2] 0d 74 [2] 02 6e [2] 1c 73 [2] 1e 72 [2] 05 74 [2] 19 73 [2] 05 5c }

  condition:
    any of them
}