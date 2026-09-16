rule TTP_XOR_QUAD_CurrentVersionRun_2e23 {
  strings:
    $key_2e23 = { 7d 4c [2] 59 42 [2] 72 6e [2] 5c 4c [2] 48 57 [2] 47 4d [2] 59 50 [2] 5b 51 [2] 40 57 [2] 5c 50 [2] 40 7f }

  condition:
    any of them
}