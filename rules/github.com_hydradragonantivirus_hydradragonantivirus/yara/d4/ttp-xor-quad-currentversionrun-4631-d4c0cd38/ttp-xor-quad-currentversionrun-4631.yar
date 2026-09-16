rule TTP_XOR_QUAD_CurrentVersionRun_4631 {
  strings:
    $key_4631 = { 15 5e [2] 31 50 [2] 1a 7c [2] 34 5e [2] 20 45 [2] 2f 5f [2] 31 42 [2] 33 43 [2] 28 45 [2] 34 42 [2] 28 6d }

  condition:
    any of them
}