rule TTP_XOR_QUAD_CurrentVersionRun_752f {
  strings:
    $key_752f = { 26 40 [2] 02 4e [2] 29 62 [2] 07 40 [2] 13 5b [2] 1c 41 [2] 02 5c [2] 00 5d [2] 1b 5b [2] 07 5c [2] 1b 73 }

  condition:
    any of them
}