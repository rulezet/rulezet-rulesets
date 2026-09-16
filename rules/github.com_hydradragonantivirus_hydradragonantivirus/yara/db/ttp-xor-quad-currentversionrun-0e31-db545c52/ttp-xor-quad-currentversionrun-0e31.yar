rule TTP_XOR_QUAD_CurrentVersionRun_0e31 {
  strings:
    $key_0e31 = { 5d 5e [2] 79 50 [2] 52 7c [2] 7c 5e [2] 68 45 [2] 67 5f [2] 79 42 [2] 7b 43 [2] 60 45 [2] 7c 42 [2] 60 6d }

  condition:
    any of them
}