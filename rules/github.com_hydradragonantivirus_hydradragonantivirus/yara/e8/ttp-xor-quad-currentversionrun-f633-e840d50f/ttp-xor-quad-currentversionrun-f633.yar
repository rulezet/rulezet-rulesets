rule TTP_XOR_QUAD_CurrentVersionRun_f633 {
  strings:
    $key_f633 = { a5 5c [2] 81 52 [2] aa 7e [2] 84 5c [2] 90 47 [2] 9f 5d [2] 81 40 [2] 83 41 [2] 98 47 [2] 84 40 [2] 98 6f }

  condition:
    any of them
}