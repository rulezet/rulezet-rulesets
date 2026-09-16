rule TTP_XOR_QUAD_CurrentVersionRun_3b78 {
  strings:
    $key_3b78 = { 68 17 [2] 4c 19 [2] 67 35 [2] 49 17 [2] 5d 0c [2] 52 16 [2] 4c 0b [2] 4e 0a [2] 55 0c [2] 49 0b [2] 55 24 }

  condition:
    any of them
}