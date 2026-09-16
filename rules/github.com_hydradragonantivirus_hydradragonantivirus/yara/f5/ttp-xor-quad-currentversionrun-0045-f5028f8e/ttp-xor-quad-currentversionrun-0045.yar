rule TTP_XOR_QUAD_CurrentVersionRun_0045 {
  strings:
    $key_0045 = { 53 2a [2] 77 24 [2] 5c 08 [2] 72 2a [2] 66 31 [2] 69 2b [2] 77 36 [2] 75 37 [2] 6e 31 [2] 72 36 [2] 6e 19 }

  condition:
    any of them
}