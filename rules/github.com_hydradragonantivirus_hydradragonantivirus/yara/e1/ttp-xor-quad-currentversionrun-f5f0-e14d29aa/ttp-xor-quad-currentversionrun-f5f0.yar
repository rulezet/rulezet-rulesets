rule TTP_XOR_QUAD_CurrentVersionRun_f5f0 {
  strings:
    $key_f5f0 = { a6 9f [2] 82 91 [2] a9 bd [2] 87 9f [2] 93 84 [2] 9c 9e [2] 82 83 [2] 80 82 [2] 9b 84 [2] 87 83 [2] 9b ac }

  condition:
    any of them
}