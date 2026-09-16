rule TTP_XOR_QUAD_CurrentVersionRun_0001 {
  strings:
    $key_0001 = { 53 6e [2] 77 60 [2] 5c 4c [2] 72 6e [2] 66 75 [2] 69 6f [2] 77 72 [2] 75 73 [2] 6e 75 [2] 72 72 [2] 6e 5d }

  condition:
    any of them
}