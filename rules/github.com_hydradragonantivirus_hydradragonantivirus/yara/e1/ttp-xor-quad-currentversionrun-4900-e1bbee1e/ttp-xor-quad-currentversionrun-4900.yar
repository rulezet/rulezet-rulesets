rule TTP_XOR_QUAD_CurrentVersionRun_4900 {
  strings:
    $key_4900 = { 1a 6f [2] 3e 61 [2] 15 4d [2] 3b 6f [2] 2f 74 [2] 20 6e [2] 3e 73 [2] 3c 72 [2] 27 74 [2] 3b 73 [2] 27 5c }

  condition:
    any of them
}