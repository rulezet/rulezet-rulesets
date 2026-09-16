rule TTP_XOR_QUAD_CurrentVersionRun_3b45 {
  strings:
    $key_3b45 = { 68 2a [2] 4c 24 [2] 67 08 [2] 49 2a [2] 5d 31 [2] 52 2b [2] 4c 36 [2] 4e 37 [2] 55 31 [2] 49 36 [2] 55 19 }

  condition:
    any of them
}