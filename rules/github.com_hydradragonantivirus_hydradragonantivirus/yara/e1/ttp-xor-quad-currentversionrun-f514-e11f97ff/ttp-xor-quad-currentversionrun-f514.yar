rule TTP_XOR_QUAD_CurrentVersionRun_f514 {
  strings:
    $key_f514 = { a6 7b [2] 82 75 [2] a9 59 [2] 87 7b [2] 93 60 [2] 9c 7a [2] 82 67 [2] 80 66 [2] 9b 60 [2] 87 67 [2] 9b 48 }

  condition:
    any of them
}