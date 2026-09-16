rule TTP_XOR_QUAD_CurrentVersionRun_f036 {
  strings:
    $key_f036 = { a3 59 [2] 87 57 [2] ac 7b [2] 82 59 [2] 96 42 [2] 99 58 [2] 87 45 [2] 85 44 [2] 9e 42 [2] 82 45 [2] 9e 6a }

  condition:
    any of them
}