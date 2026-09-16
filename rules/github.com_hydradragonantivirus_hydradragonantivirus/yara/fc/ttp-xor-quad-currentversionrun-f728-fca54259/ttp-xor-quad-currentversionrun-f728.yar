rule TTP_XOR_QUAD_CurrentVersionRun_f728 {
  strings:
    $key_f728 = { a4 47 [2] 80 49 [2] ab 65 [2] 85 47 [2] 91 5c [2] 9e 46 [2] 80 5b [2] 82 5a [2] 99 5c [2] 85 5b [2] 99 74 }

  condition:
    any of them
}