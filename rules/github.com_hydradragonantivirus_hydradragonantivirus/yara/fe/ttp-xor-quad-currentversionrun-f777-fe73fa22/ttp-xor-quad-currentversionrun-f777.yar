rule TTP_XOR_QUAD_CurrentVersionRun_f777 {
  strings:
    $key_f777 = { a4 18 [2] 80 16 [2] ab 3a [2] 85 18 [2] 91 03 [2] 9e 19 [2] 80 04 [2] 82 05 [2] 99 03 [2] 85 04 [2] 99 2b }

  condition:
    any of them
}