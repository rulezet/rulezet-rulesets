rule TTP_XOR_QUAD_CurrentVersionRun_1830 {
  strings:
    $key_1830 = { 4b 5f [2] 6f 51 [2] 44 7d [2] 6a 5f [2] 7e 44 [2] 71 5e [2] 6f 43 [2] 6d 42 [2] 76 44 [2] 6a 43 [2] 76 6c }

  condition:
    any of them
}