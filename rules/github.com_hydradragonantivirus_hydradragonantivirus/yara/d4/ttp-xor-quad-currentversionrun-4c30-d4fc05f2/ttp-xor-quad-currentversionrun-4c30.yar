rule TTP_XOR_QUAD_CurrentVersionRun_4c30 {
  strings:
    $key_4c30 = { 1f 5f [2] 3b 51 [2] 10 7d [2] 3e 5f [2] 2a 44 [2] 25 5e [2] 3b 43 [2] 39 42 [2] 22 44 [2] 3e 43 [2] 22 6c }

  condition:
    any of them
}