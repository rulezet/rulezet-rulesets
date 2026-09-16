rule TTP_XOR_QUAD_CurrentVersionRun_6b31 {
  strings:
    $key_6b31 = { 38 5e [2] 1c 50 [2] 37 7c [2] 19 5e [2] 0d 45 [2] 02 5f [2] 1c 42 [2] 1e 43 [2] 05 45 [2] 19 42 [2] 05 6d }

  condition:
    any of them
}