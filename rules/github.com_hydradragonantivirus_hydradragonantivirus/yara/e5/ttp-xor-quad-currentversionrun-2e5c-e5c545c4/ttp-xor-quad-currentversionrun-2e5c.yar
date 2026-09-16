rule TTP_XOR_QUAD_CurrentVersionRun_2e5c {
  strings:
    $key_2e5c = { 7d 33 [2] 59 3d [2] 72 11 [2] 5c 33 [2] 48 28 [2] 47 32 [2] 59 2f [2] 5b 2e [2] 40 28 [2] 5c 2f [2] 40 00 }

  condition:
    any of them
}