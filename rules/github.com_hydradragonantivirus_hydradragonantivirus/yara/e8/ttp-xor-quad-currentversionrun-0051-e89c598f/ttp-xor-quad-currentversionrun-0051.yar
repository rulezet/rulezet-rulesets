rule TTP_XOR_QUAD_CurrentVersionRun_0051 {
  strings:
    $key_0051 = { 53 3e [2] 77 30 [2] 5c 1c [2] 72 3e [2] 66 25 [2] 69 3f [2] 77 22 [2] 75 23 [2] 6e 25 [2] 72 22 [2] 6e 0d }

  condition:
    any of them
}