rule TTP_XOR_QUAD_CurrentVersionRun_2f30 {
  strings:
    $key_2f30 = { 7c 5f [2] 58 51 [2] 73 7d [2] 5d 5f [2] 49 44 [2] 46 5e [2] 58 43 [2] 5a 42 [2] 41 44 [2] 5d 43 [2] 41 6c }

  condition:
    any of them
}