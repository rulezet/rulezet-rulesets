rule TTP_XOR_QUAD_CurrentVersionRun_5631 {
  strings:
    $key_5631 = { 05 5e [2] 21 50 [2] 0a 7c [2] 24 5e [2] 30 45 [2] 3f 5f [2] 21 42 [2] 23 43 [2] 38 45 [2] 24 42 [2] 38 6d }

  condition:
    any of them
}