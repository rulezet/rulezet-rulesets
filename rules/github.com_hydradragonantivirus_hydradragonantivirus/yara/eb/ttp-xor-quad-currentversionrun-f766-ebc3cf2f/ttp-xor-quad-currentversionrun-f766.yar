rule TTP_XOR_QUAD_CurrentVersionRun_f766 {
  strings:
    $key_f766 = { a4 09 [2] 80 07 [2] ab 2b [2] 85 09 [2] 91 12 [2] 9e 08 [2] 80 15 [2] 82 14 [2] 99 12 [2] 85 15 [2] 99 3a }

  condition:
    any of them
}