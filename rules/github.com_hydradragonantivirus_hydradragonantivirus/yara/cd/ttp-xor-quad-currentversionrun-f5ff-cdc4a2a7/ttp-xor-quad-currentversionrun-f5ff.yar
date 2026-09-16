rule TTP_XOR_QUAD_CurrentVersionRun_f5ff {
  strings:
    $key_f5ff = { a6 90 [2] 82 9e [2] a9 b2 [2] 87 90 [2] 93 8b [2] 9c 91 [2] 82 8c [2] 80 8d [2] 9b 8b [2] 87 8c [2] 9b a3 }

  condition:
    any of them
}