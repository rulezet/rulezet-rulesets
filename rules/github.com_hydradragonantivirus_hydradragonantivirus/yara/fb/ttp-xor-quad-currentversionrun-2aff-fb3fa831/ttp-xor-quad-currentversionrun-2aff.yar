rule TTP_XOR_QUAD_CurrentVersionRun_2aff {
  strings:
    $key_2aff = { 79 90 [2] 5d 9e [2] 76 b2 [2] 58 90 [2] 4c 8b [2] 43 91 [2] 5d 8c [2] 5f 8d [2] 44 8b [2] 58 8c [2] 44 a3 }

  condition:
    any of them
}