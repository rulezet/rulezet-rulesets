rule TTP_XOR_QUAD_CurrentVersionRun_f210 {
  strings:
    $key_f210 = { a1 7f [2] 85 71 [2] ae 5d [2] 80 7f [2] 94 64 [2] 9b 7e [2] 85 63 [2] 87 62 [2] 9c 64 [2] 80 63 [2] 9c 4c }

  condition:
    any of them
}