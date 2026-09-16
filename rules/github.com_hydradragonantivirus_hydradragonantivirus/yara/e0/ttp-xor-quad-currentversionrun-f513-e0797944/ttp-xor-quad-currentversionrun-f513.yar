rule TTP_XOR_QUAD_CurrentVersionRun_f513 {
  strings:
    $key_f513 = { a6 7c [2] 82 72 [2] a9 5e [2] 87 7c [2] 93 67 [2] 9c 7d [2] 82 60 [2] 80 61 [2] 9b 67 [2] 87 60 [2] 9b 4f }

  condition:
    any of them
}