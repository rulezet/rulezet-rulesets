rule TTP_XOR_QUAD_CurrentVersionRun_2400 {
  strings:
    $key_2400 = { 77 6f [2] 53 61 [2] 78 4d [2] 56 6f [2] 42 74 [2] 4d 6e [2] 53 73 [2] 51 72 [2] 4a 74 [2] 56 73 [2] 4a 5c }

  condition:
    any of them
}