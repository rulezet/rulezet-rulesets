rule TTP_XOR_QUAD_CurrentVersionRun_146e {
  strings:
    $key_146e = { 47 01 [2] 63 0f [2] 48 23 [2] 66 01 [2] 72 1a [2] 7d 00 [2] 63 1d [2] 61 1c [2] 7a 1a [2] 66 1d [2] 7a 32 }

  condition:
    any of them
}