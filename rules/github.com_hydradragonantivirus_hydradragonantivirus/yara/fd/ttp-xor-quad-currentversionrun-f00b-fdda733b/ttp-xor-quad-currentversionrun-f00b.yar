rule TTP_XOR_QUAD_CurrentVersionRun_f00b {
  strings:
    $key_f00b = { a3 64 [2] 87 6a [2] ac 46 [2] 82 64 [2] 96 7f [2] 99 65 [2] 87 78 [2] 85 79 [2] 9e 7f [2] 82 78 [2] 9e 57 }

  condition:
    any of them
}