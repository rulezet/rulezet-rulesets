rule TTP_XOR_QUAD_CurrentVersionRun_0024 {
  strings:
    $key_0024 = { 53 4b [2] 77 45 [2] 5c 69 [2] 72 4b [2] 66 50 [2] 69 4a [2] 77 57 [2] 75 56 [2] 6e 50 [2] 72 57 [2] 6e 78 }

  condition:
    any of them
}