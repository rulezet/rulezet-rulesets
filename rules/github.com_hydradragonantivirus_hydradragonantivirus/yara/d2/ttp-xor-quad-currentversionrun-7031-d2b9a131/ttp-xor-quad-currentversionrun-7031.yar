rule TTP_XOR_QUAD_CurrentVersionRun_7031 {
  strings:
    $key_7031 = { 23 5e [2] 07 50 [2] 2c 7c [2] 02 5e [2] 16 45 [2] 19 5f [2] 07 42 [2] 05 43 [2] 1e 45 [2] 02 42 [2] 1e 6d }

  condition:
    any of them
}