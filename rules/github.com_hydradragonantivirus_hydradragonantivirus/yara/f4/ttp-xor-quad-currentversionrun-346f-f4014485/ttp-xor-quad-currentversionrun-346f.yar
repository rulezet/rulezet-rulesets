rule TTP_XOR_QUAD_CurrentVersionRun_346f {
  strings:
    $key_346f = { 67 00 [2] 43 0e [2] 68 22 [2] 46 00 [2] 52 1b [2] 5d 01 [2] 43 1c [2] 41 1d [2] 5a 1b [2] 46 1c [2] 5a 33 }

  condition:
    any of them
}