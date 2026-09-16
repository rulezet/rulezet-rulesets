rule TTP_XOR_QUAD_CurrentVersionRun_2f31 {
  strings:
    $key_2f31 = { 7c 5e [2] 58 50 [2] 73 7c [2] 5d 5e [2] 49 45 [2] 46 5f [2] 58 42 [2] 5a 43 [2] 41 45 [2] 5d 42 [2] 41 6d }

  condition:
    any of them
}