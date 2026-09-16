rule TTP_XOR_QUAD_CurrentVersionRun_00e9 {
  strings:
    $key_00e9 = { 53 86 [2] 77 88 [2] 5c a4 [2] 72 86 [2] 66 9d [2] 69 87 [2] 77 9a [2] 75 9b [2] 6e 9d [2] 72 9a [2] 6e b5 }

  condition:
    any of them
}