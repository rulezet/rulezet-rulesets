rule TTP_XOR_QUAD_CurrentVersionRun_720a {
  strings:
    $key_720a = { 21 65 [2] 05 6b [2] 2e 47 [2] 00 65 [2] 14 7e [2] 1b 64 [2] 05 79 [2] 07 78 [2] 1c 7e [2] 00 79 [2] 1c 56 }

  condition:
    any of them
}