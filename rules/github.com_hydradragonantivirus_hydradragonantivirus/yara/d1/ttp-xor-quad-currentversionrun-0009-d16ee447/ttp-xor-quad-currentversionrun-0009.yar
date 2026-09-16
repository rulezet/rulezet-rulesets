rule TTP_XOR_QUAD_CurrentVersionRun_0009 {
  strings:
    $key_0009 = { 53 66 [2] 77 68 [2] 5c 44 [2] 72 66 [2] 66 7d [2] 69 67 [2] 77 7a [2] 75 7b [2] 6e 7d [2] 72 7a [2] 6e 55 }

  condition:
    any of them
}