rule TTP_XOR_QUAD_CurrentVersionRun_1000 {
  strings:
    $key_1000 = { 43 6f [2] 67 61 [2] 4c 4d [2] 62 6f [2] 76 74 [2] 79 6e [2] 67 73 [2] 65 72 [2] 7e 74 [2] 62 73 [2] 7e 5c }

  condition:
    any of them
}