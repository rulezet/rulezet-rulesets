rule TTP_XOR_QUAD_CurrentVersionRun_f01b {
  strings:
    $key_f01b = { a3 74 [2] 87 7a [2] ac 56 [2] 82 74 [2] 96 6f [2] 99 75 [2] 87 68 [2] 85 69 [2] 9e 6f [2] 82 68 [2] 9e 47 }

  condition:
    any of them
}