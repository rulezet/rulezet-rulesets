rule TTP_XOR_QUAD_CurrentVersionRun_046e {
  strings:
    $key_046e = { 57 01 [2] 73 0f [2] 58 23 [2] 76 01 [2] 62 1a [2] 6d 00 [2] 73 1d [2] 71 1c [2] 6a 1a [2] 76 1d [2] 6a 32 }

  condition:
    any of them
}