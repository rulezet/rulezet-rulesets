rule TTP_XOR_QUAD_CurrentVersionRun_f071 {
  strings:
    $key_f071 = { a3 1e [2] 87 10 [2] ac 3c [2] 82 1e [2] 96 05 [2] 99 1f [2] 87 02 [2] 85 03 [2] 9e 05 [2] 82 02 [2] 9e 2d }

  condition:
    any of them
}