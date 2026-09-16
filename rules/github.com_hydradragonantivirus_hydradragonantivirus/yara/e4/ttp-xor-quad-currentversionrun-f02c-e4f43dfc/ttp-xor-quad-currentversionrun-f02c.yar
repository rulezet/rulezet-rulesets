rule TTP_XOR_QUAD_CurrentVersionRun_f02c {
  strings:
    $key_f02c = { a3 43 [2] 87 4d [2] ac 61 [2] 82 43 [2] 96 58 [2] 99 42 [2] 87 5f [2] 85 5e [2] 9e 58 [2] 82 5f [2] 9e 70 }

  condition:
    any of them
}