rule TTP_XOR_QUAD_CurrentVersionRun_f4e5 {
  strings:
    $key_f4e5 = { a7 8a [2] 83 84 [2] a8 a8 [2] 86 8a [2] 92 91 [2] 9d 8b [2] 83 96 [2] 81 97 [2] 9a 91 [2] 86 96 [2] 9a b9 }

  condition:
    any of them
}