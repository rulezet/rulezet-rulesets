rule TTP_XOR_QUAD_CurrentVersionRun_3c5c {
  strings:
    $key_3c5c = { 6f 33 [2] 4b 3d [2] 60 11 [2] 4e 33 [2] 5a 28 [2] 55 32 [2] 4b 2f [2] 49 2e [2] 52 28 [2] 4e 2f [2] 52 00 }

  condition:
    any of them
}