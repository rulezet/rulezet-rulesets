rule TTP_XOR_QUAD_CurrentVersionRun_056f {
  strings:
    $key_056f = { 56 00 [2] 72 0e [2] 59 22 [2] 77 00 [2] 63 1b [2] 6c 01 [2] 72 1c [2] 70 1d [2] 6b 1b [2] 77 1c [2] 6b 33 }

  condition:
    any of them
}