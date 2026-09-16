rule TTP_XOR_QUAD_CurrentVersionRun_f435 {
  strings:
    $key_f435 = { a7 5a [2] 83 54 [2] a8 78 [2] 86 5a [2] 92 41 [2] 9d 5b [2] 83 46 [2] 81 47 [2] 9a 41 [2] 86 46 [2] 9a 69 }

  condition:
    any of them
}