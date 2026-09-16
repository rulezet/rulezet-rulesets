rule TTP_XOR_QUAD_CurrentVersionRun_f0ff {
  strings:
    $key_f0ff = { a3 90 [2] 87 9e [2] ac b2 [2] 82 90 [2] 96 8b [2] 99 91 [2] 87 8c [2] 85 8d [2] 9e 8b [2] 82 8c [2] 9e a3 }

  condition:
    any of them
}