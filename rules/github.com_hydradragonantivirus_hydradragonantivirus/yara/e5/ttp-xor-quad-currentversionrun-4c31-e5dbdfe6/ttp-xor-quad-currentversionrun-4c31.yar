rule TTP_XOR_QUAD_CurrentVersionRun_4c31 {
  strings:
    $key_4c31 = { 1f 5e [2] 3b 50 [2] 10 7c [2] 3e 5e [2] 2a 45 [2] 25 5f [2] 3b 42 [2] 39 43 [2] 22 45 [2] 3e 42 [2] 22 6d }

  condition:
    any of them
}