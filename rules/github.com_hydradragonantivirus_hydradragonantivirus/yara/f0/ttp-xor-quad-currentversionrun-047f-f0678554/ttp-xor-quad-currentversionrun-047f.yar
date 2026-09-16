rule TTP_XOR_QUAD_CurrentVersionRun_047f {
  strings:
    $key_047f = { 57 10 [2] 73 1e [2] 58 32 [2] 76 10 [2] 62 0b [2] 6d 11 [2] 73 0c [2] 71 0d [2] 6a 0b [2] 76 0c [2] 6a 23 }

  condition:
    any of them
}