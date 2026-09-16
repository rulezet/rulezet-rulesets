rule TTP_XOR_QUAD_CurrentVersionRun_f603 {
  strings:
    $key_f603 = { a5 6c [2] 81 62 [2] aa 4e [2] 84 6c [2] 90 77 [2] 9f 6d [2] 81 70 [2] 83 71 [2] 98 77 [2] 84 70 [2] 98 5f }

  condition:
    any of them
}