rule TTP_XOR_QUAD_CurrentVersionRun_3a6e {
  strings:
    $key_3a6e = { 69 01 [2] 4d 0f [2] 66 23 [2] 48 01 [2] 5c 1a [2] 53 00 [2] 4d 1d [2] 4f 1c [2] 54 1a [2] 48 1d [2] 54 32 }

  condition:
    any of them
}