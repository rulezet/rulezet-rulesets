rule TTP_XOR_QUAD_CurrentVersionRun_f62b {
  strings:
    $key_f62b = { a5 44 [2] 81 4a [2] aa 66 [2] 84 44 [2] 90 5f [2] 9f 45 [2] 81 58 [2] 83 59 [2] 98 5f [2] 84 58 [2] 98 77 }

  condition:
    any of them
}