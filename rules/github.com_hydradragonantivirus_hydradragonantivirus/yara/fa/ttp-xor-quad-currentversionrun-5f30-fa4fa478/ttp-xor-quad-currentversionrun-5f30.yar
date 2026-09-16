rule TTP_XOR_QUAD_CurrentVersionRun_5f30 {
  strings:
    $key_5f30 = { 0c 5f [2] 28 51 [2] 03 7d [2] 2d 5f [2] 39 44 [2] 36 5e [2] 28 43 [2] 2a 42 [2] 31 44 [2] 2d 43 [2] 31 6c }

  condition:
    any of them
}