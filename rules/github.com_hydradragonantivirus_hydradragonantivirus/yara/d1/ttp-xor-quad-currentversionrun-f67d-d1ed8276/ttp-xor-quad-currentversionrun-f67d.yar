rule TTP_XOR_QUAD_CurrentVersionRun_f67d {
  strings:
    $key_f67d = { a5 12 [2] 81 1c [2] aa 30 [2] 84 12 [2] 90 09 [2] 9f 13 [2] 81 0e [2] 83 0f [2] 98 09 [2] 84 0e [2] 98 21 }

  condition:
    any of them
}