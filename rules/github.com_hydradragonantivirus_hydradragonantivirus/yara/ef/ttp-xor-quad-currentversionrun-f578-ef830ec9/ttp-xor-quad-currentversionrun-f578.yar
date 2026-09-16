rule TTP_XOR_QUAD_CurrentVersionRun_f578 {
  strings:
    $key_f578 = { a6 17 [2] 82 19 [2] a9 35 [2] 87 17 [2] 93 0c [2] 9c 16 [2] 82 0b [2] 80 0a [2] 9b 0c [2] 87 0b [2] 9b 24 }

  condition:
    any of them
}