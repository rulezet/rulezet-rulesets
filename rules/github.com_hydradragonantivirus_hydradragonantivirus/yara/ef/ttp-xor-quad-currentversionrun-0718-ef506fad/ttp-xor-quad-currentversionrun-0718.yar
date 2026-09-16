rule TTP_XOR_QUAD_CurrentVersionRun_0718 {
  strings:
    $key_0718 = { 54 77 [2] 70 79 [2] 5b 55 [2] 75 77 [2] 61 6c [2] 6e 76 [2] 70 6b [2] 72 6a [2] 69 6c [2] 75 6b [2] 69 44 }

  condition:
    any of them
}