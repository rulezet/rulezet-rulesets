rule TTP_XOR_QUAD_CurrentVersionRun_266f {
  strings:
    $key_266f = { 75 00 [2] 51 0e [2] 7a 22 [2] 54 00 [2] 40 1b [2] 4f 01 [2] 51 1c [2] 53 1d [2] 48 1b [2] 54 1c [2] 48 33 }

  condition:
    any of them
}