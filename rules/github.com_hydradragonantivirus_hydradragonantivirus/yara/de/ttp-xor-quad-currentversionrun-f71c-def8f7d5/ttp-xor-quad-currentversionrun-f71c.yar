rule TTP_XOR_QUAD_CurrentVersionRun_f71c {
  strings:
    $key_f71c = { a4 73 [2] 80 7d [2] ab 51 [2] 85 73 [2] 91 68 [2] 9e 72 [2] 80 6f [2] 82 6e [2] 99 68 [2] 85 6f [2] 99 40 }

  condition:
    any of them
}