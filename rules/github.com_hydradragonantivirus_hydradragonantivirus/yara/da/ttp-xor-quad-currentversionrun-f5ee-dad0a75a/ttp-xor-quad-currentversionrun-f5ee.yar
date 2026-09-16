rule TTP_XOR_QUAD_CurrentVersionRun_f5ee {
  strings:
    $key_f5ee = { a6 81 [2] 82 8f [2] a9 a3 [2] 87 81 [2] 93 9a [2] 9c 80 [2] 82 9d [2] 80 9c [2] 9b 9a [2] 87 9d [2] 9b b2 }

  condition:
    any of them
}