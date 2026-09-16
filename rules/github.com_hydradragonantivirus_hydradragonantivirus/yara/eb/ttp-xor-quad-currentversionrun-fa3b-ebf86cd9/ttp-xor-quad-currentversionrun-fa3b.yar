rule TTP_XOR_QUAD_CurrentVersionRun_fa3b {
  strings:
    $key_fa3b = { a9 54 [2] 8d 5a [2] a6 76 [2] 88 54 [2] 9c 4f [2] 93 55 [2] 8d 48 [2] 8f 49 [2] 94 4f [2] 88 48 [2] 94 67 }

  condition:
    any of them
}