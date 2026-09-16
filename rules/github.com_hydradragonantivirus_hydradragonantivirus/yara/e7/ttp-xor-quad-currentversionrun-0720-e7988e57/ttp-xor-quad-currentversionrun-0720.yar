rule TTP_XOR_QUAD_CurrentVersionRun_0720 {
  strings:
    $key_0720 = { 54 4f [2] 70 41 [2] 5b 6d [2] 75 4f [2] 61 54 [2] 6e 4e [2] 70 53 [2] 72 52 [2] 69 54 [2] 75 53 [2] 69 7c }

  condition:
    any of them
}