rule TTP_XOR_QUAD_CurrentVersionRun_f62e {
  strings:
    $key_f62e = { a5 41 [2] 81 4f [2] aa 63 [2] 84 41 [2] 90 5a [2] 9f 40 [2] 81 5d [2] 83 5c [2] 98 5a [2] 84 5d [2] 98 72 }

  condition:
    any of them
}