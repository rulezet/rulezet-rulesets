rule TTP_XOR_QUAD_CurrentVersionRun_f17c {
  strings:
    $key_f17c = { a2 13 [2] 86 1d [2] ad 31 [2] 83 13 [2] 97 08 [2] 98 12 [2] 86 0f [2] 84 0e [2] 9f 08 [2] 83 0f [2] 9f 20 }

  condition:
    any of them
}