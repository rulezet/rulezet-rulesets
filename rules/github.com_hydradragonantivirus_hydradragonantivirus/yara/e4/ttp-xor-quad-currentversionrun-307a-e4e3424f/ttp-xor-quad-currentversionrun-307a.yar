rule TTP_XOR_QUAD_CurrentVersionRun_307a {
  strings:
    $key_307a = { 63 15 [2] 47 1b [2] 6c 37 [2] 42 15 [2] 56 0e [2] 59 14 [2] 47 09 [2] 45 08 [2] 5e 0e [2] 42 09 [2] 5e 26 }

  condition:
    any of them
}