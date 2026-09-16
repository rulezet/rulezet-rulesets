rule TTP_XOR_QUAD_CurrentVersionRun_0d5a {
  strings:
    $key_0d5a = { 5e 35 [2] 7a 3b [2] 51 17 [2] 7f 35 [2] 6b 2e [2] 64 34 [2] 7a 29 [2] 78 28 [2] 63 2e [2] 7f 29 [2] 63 06 }

  condition:
    any of them
}