rule TTP_XOR_QUAD_CurrentVersionRun_3e30 {
  strings:
    $key_3e30 = { 6d 5f [2] 49 51 [2] 62 7d [2] 4c 5f [2] 58 44 [2] 57 5e [2] 49 43 [2] 4b 42 [2] 50 44 [2] 4c 43 [2] 50 6c }

  condition:
    any of them
}