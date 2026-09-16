rule TTP_XOR_QUAD_CurrentVersionRun_752d {
  strings:
    $key_752d = { 26 42 [2] 02 4c [2] 29 60 [2] 07 42 [2] 13 59 [2] 1c 43 [2] 02 5e [2] 00 5f [2] 1b 59 [2] 07 5e [2] 1b 71 }

  condition:
    any of them
}