rule TTP_XOR_QUAD_CurrentVersionRun_f3ef {
  strings:
    $key_f3ef = { a0 80 [2] 84 8e [2] af a2 [2] 81 80 [2] 95 9b [2] 9a 81 [2] 84 9c [2] 86 9d [2] 9d 9b [2] 81 9c [2] 9d b3 }

  condition:
    any of them
}