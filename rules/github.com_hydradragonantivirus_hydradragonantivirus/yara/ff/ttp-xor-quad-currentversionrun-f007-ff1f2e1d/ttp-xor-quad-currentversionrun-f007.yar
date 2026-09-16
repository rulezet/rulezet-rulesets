rule TTP_XOR_QUAD_CurrentVersionRun_f007 {
  strings:
    $key_f007 = { a3 68 [2] 87 66 [2] ac 4a [2] 82 68 [2] 96 73 [2] 99 69 [2] 87 74 [2] 85 75 [2] 9e 73 [2] 82 74 [2] 9e 5b }

  condition:
    any of them
}