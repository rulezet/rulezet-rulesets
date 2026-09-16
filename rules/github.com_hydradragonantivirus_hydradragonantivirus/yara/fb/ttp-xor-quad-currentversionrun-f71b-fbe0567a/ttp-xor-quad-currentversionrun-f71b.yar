rule TTP_XOR_QUAD_CurrentVersionRun_f71b {
  strings:
    $key_f71b = { a4 74 [2] 80 7a [2] ab 56 [2] 85 74 [2] 91 6f [2] 9e 75 [2] 80 68 [2] 82 69 [2] 99 6f [2] 85 68 [2] 99 47 }

  condition:
    any of them
}