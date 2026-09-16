rule TTP_XOR_QUAD_CurrentVersionRun_770d {
  strings:
    $key_770d = { 24 62 [2] 00 6c [2] 2b 40 [2] 05 62 [2] 11 79 [2] 1e 63 [2] 00 7e [2] 02 7f [2] 19 79 [2] 05 7e [2] 19 51 }

  condition:
    any of them
}