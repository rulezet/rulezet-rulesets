rule TTP_XOR_QUAD_CurrentVersionRun_f02d {
  strings:
    $key_f02d = { a3 42 [2] 87 4c [2] ac 60 [2] 82 42 [2] 96 59 [2] 99 43 [2] 87 5e [2] 85 5f [2] 9e 59 [2] 82 5e [2] 9e 71 }

  condition:
    any of them
}