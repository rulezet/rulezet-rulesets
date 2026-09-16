rule TTP_XOR_QUAD_CurrentVersionRun_0031 {
  strings:
    $key_0031 = { 53 5e [2] 77 50 [2] 5c 7c [2] 72 5e [2] 66 45 [2] 69 5f [2] 77 42 [2] 75 43 [2] 6e 45 [2] 72 42 [2] 6e 6d }

  condition:
    any of them
}