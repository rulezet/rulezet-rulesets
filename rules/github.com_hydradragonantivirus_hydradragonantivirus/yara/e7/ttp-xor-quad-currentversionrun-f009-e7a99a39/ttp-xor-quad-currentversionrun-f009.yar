rule TTP_XOR_QUAD_CurrentVersionRun_f009 {
  strings:
    $key_f009 = { a3 66 [2] 87 68 [2] ac 44 [2] 82 66 [2] 96 7d [2] 99 67 [2] 87 7a [2] 85 7b [2] 9e 7d [2] 82 7a [2] 9e 55 }

  condition:
    any of them
}