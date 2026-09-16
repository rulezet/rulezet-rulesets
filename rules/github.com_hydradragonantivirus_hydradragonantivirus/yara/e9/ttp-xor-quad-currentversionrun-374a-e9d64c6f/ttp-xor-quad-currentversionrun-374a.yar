rule TTP_XOR_QUAD_CurrentVersionRun_374a {
  strings:
    $key_374a = { 64 25 [2] 40 2b [2] 6b 07 [2] 45 25 [2] 51 3e [2] 5e 24 [2] 40 39 [2] 42 38 [2] 59 3e [2] 45 39 [2] 59 16 }

  condition:
    any of them
}