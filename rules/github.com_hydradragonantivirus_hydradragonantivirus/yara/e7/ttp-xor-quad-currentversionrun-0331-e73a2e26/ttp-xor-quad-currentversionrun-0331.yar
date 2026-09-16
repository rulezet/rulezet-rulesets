rule TTP_XOR_QUAD_CurrentVersionRun_0331 {
  strings:
    $key_0331 = { 50 5e [2] 74 50 [2] 5f 7c [2] 71 5e [2] 65 45 [2] 6a 5f [2] 74 42 [2] 76 43 [2] 6d 45 [2] 71 42 [2] 6d 6d }

  condition:
    any of them
}