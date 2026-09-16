rule TTP_XOR_QUAD_CurrentVersionRun_4931 {
  strings:
    $key_4931 = { 1a 5e [2] 3e 50 [2] 15 7c [2] 3b 5e [2] 2f 45 [2] 20 5f [2] 3e 42 [2] 3c 43 [2] 27 45 [2] 3b 42 [2] 27 6d }

  condition:
    any of them
}