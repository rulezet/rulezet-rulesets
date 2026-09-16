rule TTP_XOR_QUAD_CurrentVersionRun_f017 {
  strings:
    $key_f017 = { a3 78 [2] 87 76 [2] ac 5a [2] 82 78 [2] 96 63 [2] 99 79 [2] 87 64 [2] 85 65 [2] 9e 63 [2] 82 64 [2] 9e 4b }

  condition:
    any of them
}