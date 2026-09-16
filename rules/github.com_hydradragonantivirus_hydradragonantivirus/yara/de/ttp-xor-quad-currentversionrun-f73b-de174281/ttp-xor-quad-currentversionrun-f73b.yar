rule TTP_XOR_QUAD_CurrentVersionRun_f73b {
  strings:
    $key_f73b = { a4 54 [2] 80 5a [2] ab 76 [2] 85 54 [2] 91 4f [2] 9e 55 [2] 80 48 [2] 82 49 [2] 99 4f [2] 85 48 [2] 99 67 }

  condition:
    any of them
}