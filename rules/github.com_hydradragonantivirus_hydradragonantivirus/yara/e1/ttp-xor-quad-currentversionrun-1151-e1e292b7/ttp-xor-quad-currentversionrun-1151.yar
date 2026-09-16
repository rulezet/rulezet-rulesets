rule TTP_XOR_QUAD_CurrentVersionRun_1151 {
  strings:
    $key_1151 = { 42 3e [2] 66 30 [2] 4d 1c [2] 63 3e [2] 77 25 [2] 78 3f [2] 66 22 [2] 64 23 [2] 7f 25 [2] 63 22 [2] 7f 0d }

  condition:
    any of them
}