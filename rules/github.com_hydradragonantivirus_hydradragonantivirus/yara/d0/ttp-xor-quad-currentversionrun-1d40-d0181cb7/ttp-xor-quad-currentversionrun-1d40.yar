rule TTP_XOR_QUAD_CurrentVersionRun_1d40 {
  strings:
    $key_1d40 = { 4e 2f [2] 6a 21 [2] 41 0d [2] 6f 2f [2] 7b 34 [2] 74 2e [2] 6a 33 [2] 68 32 [2] 73 34 [2] 6f 33 [2] 73 1c }

  condition:
    any of them
}