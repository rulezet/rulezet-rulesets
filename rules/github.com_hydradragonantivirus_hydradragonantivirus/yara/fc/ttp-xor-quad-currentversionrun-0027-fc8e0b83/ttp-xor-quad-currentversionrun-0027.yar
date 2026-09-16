rule TTP_XOR_QUAD_CurrentVersionRun_0027 {
  strings:
    $key_0027 = { 53 48 [2] 77 46 [2] 5c 6a [2] 72 48 [2] 66 53 [2] 69 49 [2] 77 54 [2] 75 55 [2] 6e 53 [2] 72 54 [2] 6e 7b }

  condition:
    any of them
}