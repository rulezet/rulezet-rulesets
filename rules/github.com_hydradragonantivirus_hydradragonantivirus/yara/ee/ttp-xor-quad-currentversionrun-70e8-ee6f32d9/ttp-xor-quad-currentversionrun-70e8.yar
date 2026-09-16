rule TTP_XOR_QUAD_CurrentVersionRun_70e8 {
  strings:
    $key_70e8 = { 23 87 [2] 07 89 [2] 2c a5 [2] 02 87 [2] 16 9c [2] 19 86 [2] 07 9b [2] 05 9a [2] 1e 9c [2] 02 9b [2] 1e b4 }

  condition:
    any of them
}