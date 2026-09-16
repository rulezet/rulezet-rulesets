rule TTP_XOR_QUAD_CurrentVersionRun_f529 {
  strings:
    $key_f529 = { a6 46 [2] 82 48 [2] a9 64 [2] 87 46 [2] 93 5d [2] 9c 47 [2] 82 5a [2] 80 5b [2] 9b 5d [2] 87 5a [2] 9b 75 }

  condition:
    any of them
}