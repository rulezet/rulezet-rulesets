rule TTP_XOR_QUAD_CurrentVersionRun_7731 {
  strings:
    $key_7731 = { 24 5e [2] 00 50 [2] 2b 7c [2] 05 5e [2] 11 45 [2] 1e 5f [2] 00 42 [2] 02 43 [2] 19 45 [2] 05 42 [2] 19 6d }

  condition:
    any of them
}