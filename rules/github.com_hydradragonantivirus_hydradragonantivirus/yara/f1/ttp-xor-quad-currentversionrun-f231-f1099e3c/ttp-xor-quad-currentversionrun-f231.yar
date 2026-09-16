rule TTP_XOR_QUAD_CurrentVersionRun_f231 {
  strings:
    $key_f231 = { a1 5e [2] 85 50 [2] ae 7c [2] 80 5e [2] 94 45 [2] 9b 5f [2] 85 42 [2] 87 43 [2] 9c 45 [2] 80 42 [2] 9c 6d }

  condition:
    any of them
}