rule TTP_XOR_QUAD_CurrentVersionRun_7a00 {
  strings:
    $key_7a00 = { 29 6f [2] 0d 61 [2] 26 4d [2] 08 6f [2] 1c 74 [2] 13 6e [2] 0d 73 [2] 0f 72 [2] 14 74 [2] 08 73 [2] 14 5c }

  condition:
    any of them
}