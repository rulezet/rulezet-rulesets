rule TTP_XOR_QUAD_CurrentVersionRun_f7e5 {
  strings:
    $key_f7e5 = { a4 8a [2] 80 84 [2] ab a8 [2] 85 8a [2] 91 91 [2] 9e 8b [2] 80 96 [2] 82 97 [2] 99 91 [2] 85 96 [2] 99 b9 }

  condition:
    any of them
}