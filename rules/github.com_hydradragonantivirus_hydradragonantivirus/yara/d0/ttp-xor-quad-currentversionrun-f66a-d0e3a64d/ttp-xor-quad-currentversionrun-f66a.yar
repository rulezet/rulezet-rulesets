rule TTP_XOR_QUAD_CurrentVersionRun_f66a {
  strings:
    $key_f66a = { a5 05 [2] 81 0b [2] aa 27 [2] 84 05 [2] 90 1e [2] 9f 04 [2] 81 19 [2] 83 18 [2] 98 1e [2] 84 19 [2] 98 36 }

  condition:
    any of them
}