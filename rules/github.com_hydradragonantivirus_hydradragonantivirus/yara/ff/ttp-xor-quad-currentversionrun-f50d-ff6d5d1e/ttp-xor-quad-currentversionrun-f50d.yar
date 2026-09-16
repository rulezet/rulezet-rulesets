rule TTP_XOR_QUAD_CurrentVersionRun_f50d {
  strings:
    $key_f50d = { a6 62 [2] 82 6c [2] a9 40 [2] 87 62 [2] 93 79 [2] 9c 63 [2] 82 7e [2] 80 7f [2] 9b 79 [2] 87 7e [2] 9b 51 }

  condition:
    any of them
}