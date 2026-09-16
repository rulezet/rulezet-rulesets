rule TTP_XOR_QUAD_CurrentVersionRun_6330 {
  strings:
    $key_6330 = { 30 5f [2] 14 51 [2] 3f 7d [2] 11 5f [2] 05 44 [2] 0a 5e [2] 14 43 [2] 16 42 [2] 0d 44 [2] 11 43 [2] 0d 6c }

  condition:
    any of them
}