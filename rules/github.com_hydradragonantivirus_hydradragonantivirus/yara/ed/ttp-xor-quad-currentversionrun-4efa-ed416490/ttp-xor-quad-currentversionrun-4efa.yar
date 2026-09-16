rule TTP_XOR_QUAD_CurrentVersionRun_4efa {
  strings:
    $key_4efa = { 1d 95 [2] 39 9b [2] 12 b7 [2] 3c 95 [2] 28 8e [2] 27 94 [2] 39 89 [2] 3b 88 [2] 20 8e [2] 3c 89 [2] 20 a6 }

  condition:
    any of them
}