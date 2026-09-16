rule TTP_XOR_QUAD_CurrentVersionRun_f7f8 {
  strings:
    $key_f7f8 = { a4 97 [2] 80 99 [2] ab b5 [2] 85 97 [2] 91 8c [2] 9e 96 [2] 80 8b [2] 82 8a [2] 99 8c [2] 85 8b [2] 99 a4 }

  condition:
    any of them
}