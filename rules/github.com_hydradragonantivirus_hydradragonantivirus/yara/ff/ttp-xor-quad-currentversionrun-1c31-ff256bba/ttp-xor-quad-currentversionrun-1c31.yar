rule TTP_XOR_QUAD_CurrentVersionRun_1c31 {
  strings:
    $key_1c31 = { 4f 5e [2] 6b 50 [2] 40 7c [2] 6e 5e [2] 7a 45 [2] 75 5f [2] 6b 42 [2] 69 43 [2] 72 45 [2] 6e 42 [2] 72 6d }

  condition:
    any of them
}