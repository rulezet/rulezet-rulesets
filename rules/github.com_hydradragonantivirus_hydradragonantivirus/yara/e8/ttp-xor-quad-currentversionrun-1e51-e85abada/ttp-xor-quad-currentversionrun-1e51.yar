rule TTP_XOR_QUAD_CurrentVersionRun_1e51 {
  strings:
    $key_1e51 = { 4d 3e [2] 69 30 [2] 42 1c [2] 6c 3e [2] 78 25 [2] 77 3f [2] 69 22 [2] 6b 23 [2] 70 25 [2] 6c 22 [2] 70 0d }

  condition:
    any of them
}