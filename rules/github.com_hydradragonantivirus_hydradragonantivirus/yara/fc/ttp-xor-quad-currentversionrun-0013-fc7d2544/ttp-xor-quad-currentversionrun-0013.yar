rule TTP_XOR_QUAD_CurrentVersionRun_0013 {
  strings:
    $key_0013 = { 53 7c [2] 77 72 [2] 5c 5e [2] 72 7c [2] 66 67 [2] 69 7d [2] 77 60 [2] 75 61 [2] 6e 67 [2] 72 60 [2] 6e 4f }

  condition:
    any of them
}