rule TTP_XOR_QUAD_CurrentVersionRun_346e {
  strings:
    $key_346e = { 67 01 [2] 43 0f [2] 68 23 [2] 46 01 [2] 52 1a [2] 5d 00 [2] 43 1d [2] 41 1c [2] 5a 1a [2] 46 1d [2] 5a 32 }

  condition:
    any of them
}