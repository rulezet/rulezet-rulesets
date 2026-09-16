rule TTP_XOR_QUAD_CurrentVersionRun_f51f {
  strings:
    $key_f51f = { a6 70 [2] 82 7e [2] a9 52 [2] 87 70 [2] 93 6b [2] 9c 71 [2] 82 6c [2] 80 6d [2] 9b 6b [2] 87 6c [2] 9b 43 }

  condition:
    any of them
}