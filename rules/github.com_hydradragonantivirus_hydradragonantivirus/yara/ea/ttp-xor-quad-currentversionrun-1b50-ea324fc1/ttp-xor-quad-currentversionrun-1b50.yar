rule TTP_XOR_QUAD_CurrentVersionRun_1b50 {
  strings:
    $key_1b50 = { 48 3f [2] 6c 31 [2] 47 1d [2] 69 3f [2] 7d 24 [2] 72 3e [2] 6c 23 [2] 6e 22 [2] 75 24 [2] 69 23 [2] 75 0c }

  condition:
    any of them
}