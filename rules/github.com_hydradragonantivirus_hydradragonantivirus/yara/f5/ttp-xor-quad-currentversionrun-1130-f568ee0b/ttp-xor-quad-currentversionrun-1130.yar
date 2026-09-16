rule TTP_XOR_QUAD_CurrentVersionRun_1130 {
  strings:
    $key_1130 = { 42 5f [2] 66 51 [2] 4d 7d [2] 63 5f [2] 77 44 [2] 78 5e [2] 66 43 [2] 64 42 [2] 7f 44 [2] 63 43 [2] 7f 6c }

  condition:
    any of them
}