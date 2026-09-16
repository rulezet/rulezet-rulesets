rule TTP_XOR_QUAD_CurrentVersionRun_0cec {
  strings:
    $key_0cec = { 5f 83 [2] 7b 8d [2] 50 a1 [2] 7e 83 [2] 6a 98 [2] 65 82 [2] 7b 9f [2] 79 9e [2] 62 98 [2] 7e 9f [2] 62 b0 }

  condition:
    any of them
}