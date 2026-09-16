rule TTP_XOR_QUAD_CurrentVersionRun_f24b {
  strings:
    $key_f24b = { a1 24 [2] 85 2a [2] ae 06 [2] 80 24 [2] 94 3f [2] 9b 25 [2] 85 38 [2] 87 39 [2] 9c 3f [2] 80 38 [2] 9c 17 }

  condition:
    any of them
}