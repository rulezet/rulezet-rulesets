rule TTP_XOR_QUAD_CurrentVersionRun_0033 {
  strings:
    $key_0033 = { 53 5c [2] 77 52 [2] 5c 7e [2] 72 5c [2] 66 47 [2] 69 5d [2] 77 40 [2] 75 41 [2] 6e 47 [2] 72 40 [2] 6e 6f }

  condition:
    any of them
}