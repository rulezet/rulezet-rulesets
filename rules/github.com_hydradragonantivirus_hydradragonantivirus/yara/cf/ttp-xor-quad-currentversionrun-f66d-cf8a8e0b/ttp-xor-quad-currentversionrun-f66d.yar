rule TTP_XOR_QUAD_CurrentVersionRun_f66d {
  strings:
    $key_f66d = { a5 02 [2] 81 0c [2] aa 20 [2] 84 02 [2] 90 19 [2] 9f 03 [2] 81 1e [2] 83 1f [2] 98 19 [2] 84 1e [2] 98 31 }

  condition:
    any of them
}