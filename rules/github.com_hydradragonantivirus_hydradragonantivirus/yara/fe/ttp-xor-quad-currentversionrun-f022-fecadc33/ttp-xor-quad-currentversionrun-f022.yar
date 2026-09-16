rule TTP_XOR_QUAD_CurrentVersionRun_f022 {
  strings:
    $key_f022 = { a3 4d [2] 87 43 [2] ac 6f [2] 82 4d [2] 96 56 [2] 99 4c [2] 87 51 [2] 85 50 [2] 9e 56 [2] 82 51 [2] 9e 7e }

  condition:
    any of them
}