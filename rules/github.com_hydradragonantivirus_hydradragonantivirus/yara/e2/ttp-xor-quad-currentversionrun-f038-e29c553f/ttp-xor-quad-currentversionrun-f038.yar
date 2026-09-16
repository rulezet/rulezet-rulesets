rule TTP_XOR_QUAD_CurrentVersionRun_f038 {
  strings:
    $key_f038 = { a3 57 [2] 87 59 [2] ac 75 [2] 82 57 [2] 96 4c [2] 99 56 [2] 87 4b [2] 85 4a [2] 9e 4c [2] 82 4b [2] 9e 64 }

  condition:
    any of them
}