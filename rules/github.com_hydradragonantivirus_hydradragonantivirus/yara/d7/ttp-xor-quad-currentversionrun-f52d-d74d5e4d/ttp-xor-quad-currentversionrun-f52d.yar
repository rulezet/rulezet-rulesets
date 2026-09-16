rule TTP_XOR_QUAD_CurrentVersionRun_f52d {
  strings:
    $key_f52d = { a6 42 [2] 82 4c [2] a9 60 [2] 87 42 [2] 93 59 [2] 9c 43 [2] 82 5e [2] 80 5f [2] 9b 59 [2] 87 5e [2] 9b 71 }

  condition:
    any of them
}