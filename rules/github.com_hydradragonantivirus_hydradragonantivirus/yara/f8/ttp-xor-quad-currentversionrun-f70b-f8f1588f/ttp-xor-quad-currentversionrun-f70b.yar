rule TTP_XOR_QUAD_CurrentVersionRun_f70b {
  strings:
    $key_f70b = { a4 64 [2] 80 6a [2] ab 46 [2] 85 64 [2] 91 7f [2] 9e 65 [2] 80 78 [2] 82 79 [2] 99 7f [2] 85 78 [2] 99 57 }

  condition:
    any of them
}