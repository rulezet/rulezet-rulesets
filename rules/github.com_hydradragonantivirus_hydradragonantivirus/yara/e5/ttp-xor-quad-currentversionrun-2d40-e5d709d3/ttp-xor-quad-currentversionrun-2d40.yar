rule TTP_XOR_QUAD_CurrentVersionRun_2d40 {
  strings:
    $key_2d40 = { 7e 2f [2] 5a 21 [2] 71 0d [2] 5f 2f [2] 4b 34 [2] 44 2e [2] 5a 33 [2] 58 32 [2] 43 34 [2] 5f 33 [2] 43 1c }

  condition:
    any of them
}