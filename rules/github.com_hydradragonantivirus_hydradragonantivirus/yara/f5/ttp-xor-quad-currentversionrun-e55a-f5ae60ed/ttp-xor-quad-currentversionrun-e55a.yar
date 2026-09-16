rule TTP_XOR_QUAD_CurrentVersionRun_e55a {
  strings:
    $key_e55a = { b6 35 [2] 92 3b [2] b9 17 [2] 97 35 [2] 83 2e [2] 8c 34 [2] 92 29 [2] 90 28 [2] 8b 2e [2] 97 29 [2] 8b 06 }

  condition:
    any of them
}