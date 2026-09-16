rule TTP_XOR_QUAD_CurrentVersionRun_7800 {
  strings:
    $key_7800 = { 2b 6f [2] 0f 61 [2] 24 4d [2] 0a 6f [2] 1e 74 [2] 11 6e [2] 0f 73 [2] 0d 72 [2] 16 74 [2] 0a 73 [2] 16 5c }

  condition:
    any of them
}