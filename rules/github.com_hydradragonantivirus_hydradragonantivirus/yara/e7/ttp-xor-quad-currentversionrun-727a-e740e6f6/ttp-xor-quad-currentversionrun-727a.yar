rule TTP_XOR_QUAD_CurrentVersionRun_727a {
  strings:
    $key_727a = { 21 15 [2] 05 1b [2] 2e 37 [2] 00 15 [2] 14 0e [2] 1b 14 [2] 05 09 [2] 07 08 [2] 1c 0e [2] 00 09 [2] 1c 26 }

  condition:
    any of them
}