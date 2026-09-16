rule TTP_XOR_QUAD_CurrentVersionRun_2b41 {
  strings:
    $key_2b41 = { 78 2e [2] 5c 20 [2] 77 0c [2] 59 2e [2] 4d 35 [2] 42 2f [2] 5c 32 [2] 5e 33 [2] 45 35 [2] 59 32 [2] 45 1d }

  condition:
    any of them
}