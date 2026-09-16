rule TTP_XOR_QUAD_CurrentVersionRun_1cec {
  strings:
    $key_1cec = { 4f 83 [2] 6b 8d [2] 40 a1 [2] 6e 83 [2] 7a 98 [2] 75 82 [2] 6b 9f [2] 69 9e [2] 72 98 [2] 6e 9f [2] 72 b0 }

  condition:
    any of them
}