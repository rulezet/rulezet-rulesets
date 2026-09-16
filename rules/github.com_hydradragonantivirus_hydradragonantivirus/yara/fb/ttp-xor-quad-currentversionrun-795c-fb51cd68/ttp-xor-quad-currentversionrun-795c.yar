rule TTP_XOR_QUAD_CurrentVersionRun_795c {
  strings:
    $key_795c = { 2a 33 [2] 0e 3d [2] 25 11 [2] 0b 33 [2] 1f 28 [2] 10 32 [2] 0e 2f [2] 0c 2e [2] 17 28 [2] 0b 2f [2] 17 00 }

  condition:
    any of them
}