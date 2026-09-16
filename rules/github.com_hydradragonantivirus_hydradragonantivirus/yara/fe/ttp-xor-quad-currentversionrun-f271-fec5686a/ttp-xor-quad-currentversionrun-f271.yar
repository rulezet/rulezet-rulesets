rule TTP_XOR_QUAD_CurrentVersionRun_f271 {
  strings:
    $key_f271 = { a1 1e [2] 85 10 [2] ae 3c [2] 80 1e [2] 94 05 [2] 9b 1f [2] 85 02 [2] 87 03 [2] 9c 05 [2] 80 02 [2] 9c 2d }

  condition:
    any of them
}