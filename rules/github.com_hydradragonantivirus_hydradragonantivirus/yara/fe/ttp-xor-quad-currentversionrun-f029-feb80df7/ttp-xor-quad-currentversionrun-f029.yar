rule TTP_XOR_QUAD_CurrentVersionRun_f029 {
  strings:
    $key_f029 = { a3 46 [2] 87 48 [2] ac 64 [2] 82 46 [2] 96 5d [2] 99 47 [2] 87 5a [2] 85 5b [2] 9e 5d [2] 82 5a [2] 9e 75 }

  condition:
    any of them
}