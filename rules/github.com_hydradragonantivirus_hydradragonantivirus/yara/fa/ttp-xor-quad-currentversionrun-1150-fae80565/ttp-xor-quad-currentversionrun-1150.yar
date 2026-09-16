rule TTP_XOR_QUAD_CurrentVersionRun_1150 {
  strings:
    $key_1150 = { 42 3f [2] 66 31 [2] 4d 1d [2] 63 3f [2] 77 24 [2] 78 3e [2] 66 23 [2] 64 22 [2] 7f 24 [2] 63 23 [2] 7f 0c }

  condition:
    any of them
}