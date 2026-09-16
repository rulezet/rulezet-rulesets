rule TTP_XOR_QUAD_CurrentVersionRun_7d40 {
  strings:
    $key_7d40 = { 2e 2f [2] 0a 21 [2] 21 0d [2] 0f 2f [2] 1b 34 [2] 14 2e [2] 0a 33 [2] 08 32 [2] 13 34 [2] 0f 33 [2] 13 1c }

  condition:
    any of them
}