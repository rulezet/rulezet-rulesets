rule TTP_XOR_QUAD_CurrentVersionRun_2b31 {
  strings:
    $key_2b31 = { 78 5e [2] 5c 50 [2] 77 7c [2] 59 5e [2] 4d 45 [2] 42 5f [2] 5c 42 [2] 5e 43 [2] 45 45 [2] 59 42 [2] 45 6d }

  condition:
    any of them
}