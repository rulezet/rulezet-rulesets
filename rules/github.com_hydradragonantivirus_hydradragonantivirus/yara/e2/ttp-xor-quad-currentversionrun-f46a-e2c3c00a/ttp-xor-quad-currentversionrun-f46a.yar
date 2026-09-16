rule TTP_XOR_QUAD_CurrentVersionRun_f46a {
  strings:
    $key_f46a = { a7 05 [2] 83 0b [2] a8 27 [2] 86 05 [2] 92 1e [2] 9d 04 [2] 83 19 [2] 81 18 [2] 9a 1e [2] 86 19 [2] 9a 36 }

  condition:
    any of them
}