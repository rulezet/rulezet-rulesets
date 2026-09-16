rule TTP_XOR_QUAD_CurrentVersionRun_f203 {
  strings:
    $key_f203 = { a1 6c [2] 85 62 [2] ae 4e [2] 80 6c [2] 94 77 [2] 9b 6d [2] 85 70 [2] 87 71 [2] 9c 77 [2] 80 70 [2] 9c 5f }

  condition:
    any of them
}