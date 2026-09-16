rule TTP_XOR_QUAD_CurrentVersionRun_f2ef {
  strings:
    $key_f2ef = { a1 80 [2] 85 8e [2] ae a2 [2] 80 80 [2] 94 9b [2] 9b 81 [2] 85 9c [2] 87 9d [2] 9c 9b [2] 80 9c [2] 9c b3 }

  condition:
    any of them
}