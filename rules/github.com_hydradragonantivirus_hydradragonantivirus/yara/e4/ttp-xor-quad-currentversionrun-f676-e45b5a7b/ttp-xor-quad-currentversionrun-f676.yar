rule TTP_XOR_QUAD_CurrentVersionRun_f676 {
  strings:
    $key_f676 = { a5 19 [2] 81 17 [2] aa 3b [2] 84 19 [2] 90 02 [2] 9f 18 [2] 81 05 [2] 83 04 [2] 98 02 [2] 84 05 [2] 98 2a }

  condition:
    any of them
}