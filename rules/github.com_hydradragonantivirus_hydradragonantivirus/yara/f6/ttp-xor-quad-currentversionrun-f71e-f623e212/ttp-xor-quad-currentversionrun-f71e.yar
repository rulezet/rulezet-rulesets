rule TTP_XOR_QUAD_CurrentVersionRun_f71e {
  strings:
    $key_f71e = { a4 71 [2] 80 7f [2] ab 53 [2] 85 71 [2] 91 6a [2] 9e 70 [2] 80 6d [2] 82 6c [2] 99 6a [2] 85 6d [2] 99 42 }

  condition:
    any of them
}