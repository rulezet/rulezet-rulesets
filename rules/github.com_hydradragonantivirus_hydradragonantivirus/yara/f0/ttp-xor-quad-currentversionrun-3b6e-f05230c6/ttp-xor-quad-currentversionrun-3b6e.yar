rule TTP_XOR_QUAD_CurrentVersionRun_3b6e {
  strings:
    $key_3b6e = { 68 01 [2] 4c 0f [2] 67 23 [2] 49 01 [2] 5d 1a [2] 52 00 [2] 4c 1d [2] 4e 1c [2] 55 1a [2] 49 1d [2] 55 32 }

  condition:
    any of them
}