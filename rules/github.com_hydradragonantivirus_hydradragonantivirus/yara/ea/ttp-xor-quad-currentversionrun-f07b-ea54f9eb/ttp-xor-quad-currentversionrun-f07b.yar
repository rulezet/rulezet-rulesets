rule TTP_XOR_QUAD_CurrentVersionRun_f07b {
  strings:
    $key_f07b = { a3 14 [2] 87 1a [2] ac 36 [2] 82 14 [2] 96 0f [2] 99 15 [2] 87 08 [2] 85 09 [2] 9e 0f [2] 82 08 [2] 9e 27 }

  condition:
    any of them
}