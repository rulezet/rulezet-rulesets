rule TTP_XOR_QUAD_CurrentVersionRun_305a {
  strings:
    $key_305a = { 63 35 [2] 47 3b [2] 6c 17 [2] 42 35 [2] 56 2e [2] 59 34 [2] 47 29 [2] 45 28 [2] 5e 2e [2] 42 29 [2] 5e 06 }

  condition:
    any of them
}