rule TTP_XOR_QUAD_CurrentVersionRun_f414 {
  strings:
    $key_f414 = { a7 7b [2] 83 75 [2] a8 59 [2] 86 7b [2] 92 60 [2] 9d 7a [2] 83 67 [2] 81 66 [2] 9a 60 [2] 86 67 [2] 9a 48 }

  condition:
    any of them
}