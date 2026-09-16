rule TTP_XOR_QUAD_CurrentVersionRun_7d30 {
  strings:
    $key_7d30 = { 2e 5f [2] 0a 51 [2] 21 7d [2] 0f 5f [2] 1b 44 [2] 14 5e [2] 0a 43 [2] 08 42 [2] 13 44 [2] 0f 43 [2] 13 6c }

  condition:
    any of them
}