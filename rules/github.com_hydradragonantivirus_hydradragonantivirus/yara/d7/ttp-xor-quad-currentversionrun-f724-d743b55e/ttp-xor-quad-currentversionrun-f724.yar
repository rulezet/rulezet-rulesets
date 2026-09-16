rule TTP_XOR_QUAD_CurrentVersionRun_f724 {
  strings:
    $key_f724 = { a4 4b [2] 80 45 [2] ab 69 [2] 85 4b [2] 91 50 [2] 9e 4a [2] 80 57 [2] 82 56 [2] 99 50 [2] 85 57 [2] 99 78 }

  condition:
    any of them
}