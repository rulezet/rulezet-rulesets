rule TTP_XOR_QUAD_CurrentVersionRun_f63a {
  strings:
    $key_f63a = { a5 55 [2] 81 5b [2] aa 77 [2] 84 55 [2] 90 4e [2] 9f 54 [2] 81 49 [2] 83 48 [2] 98 4e [2] 84 49 [2] 98 66 }

  condition:
    any of them
}