rule TTP_XOR_QUAD_CurrentVersionRun_6efa {
  strings:
    $key_6efa = { 3d 95 [2] 19 9b [2] 32 b7 [2] 1c 95 [2] 08 8e [2] 07 94 [2] 19 89 [2] 1b 88 [2] 00 8e [2] 1c 89 [2] 00 a6 }

  condition:
    any of them
}