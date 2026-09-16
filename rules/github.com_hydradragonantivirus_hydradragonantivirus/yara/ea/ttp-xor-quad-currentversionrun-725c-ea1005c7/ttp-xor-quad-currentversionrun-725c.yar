rule TTP_XOR_QUAD_CurrentVersionRun_725c {
  strings:
    $key_725c = { 21 33 [2] 05 3d [2] 2e 11 [2] 00 33 [2] 14 28 [2] 1b 32 [2] 05 2f [2] 07 2e [2] 1c 28 [2] 00 2f [2] 1c 00 }

  condition:
    any of them
}