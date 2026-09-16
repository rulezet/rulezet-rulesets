rule TTP_XOR_QUAD_CurrentVersionRun_f721 {
  strings:
    $key_f721 = { a4 4e [2] 80 40 [2] ab 6c [2] 85 4e [2] 91 55 [2] 9e 4f [2] 80 52 [2] 82 53 [2] 99 55 [2] 85 52 [2] 99 7d }

  condition:
    any of them
}