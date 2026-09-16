rule TTP_XOR_QUAD_CurrentVersionRun_156f {
  strings:
    $key_156f = { 46 00 [2] 62 0e [2] 49 22 [2] 67 00 [2] 73 1b [2] 7c 01 [2] 62 1c [2] 60 1d [2] 7b 1b [2] 67 1c [2] 7b 33 }

  condition:
    any of them
}