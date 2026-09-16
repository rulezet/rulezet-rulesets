rule TTP_XOR_QUAD_CurrentVersionRun_3523 {
  strings:
    $key_3523 = { 66 4c [2] 42 42 [2] 69 6e [2] 47 4c [2] 53 57 [2] 5c 4d [2] 42 50 [2] 40 51 [2] 5b 57 [2] 47 50 [2] 5b 7f }

  condition:
    any of them
}