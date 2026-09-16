rule TTP_XOR_QUAD_CurrentVersionRun_7d50 {
  strings:
    $key_7d50 = { 2e 3f [2] 0a 31 [2] 21 1d [2] 0f 3f [2] 1b 24 [2] 14 3e [2] 0a 23 [2] 08 22 [2] 13 24 [2] 0f 23 [2] 13 0c }

  condition:
    any of them
}