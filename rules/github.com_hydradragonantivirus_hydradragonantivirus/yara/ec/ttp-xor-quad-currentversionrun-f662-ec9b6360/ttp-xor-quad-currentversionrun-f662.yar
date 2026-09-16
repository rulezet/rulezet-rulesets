rule TTP_XOR_QUAD_CurrentVersionRun_f662 {
  strings:
    $key_f662 = { a5 0d [2] 81 03 [2] aa 2f [2] 84 0d [2] 90 16 [2] 9f 0c [2] 81 11 [2] 83 10 [2] 98 16 [2] 84 11 [2] 98 3e }

  condition:
    any of them
}