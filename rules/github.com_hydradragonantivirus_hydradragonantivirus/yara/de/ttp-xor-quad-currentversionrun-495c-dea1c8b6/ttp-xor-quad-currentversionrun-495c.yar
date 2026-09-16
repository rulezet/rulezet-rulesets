rule TTP_XOR_QUAD_CurrentVersionRun_495c {
  strings:
    $key_495c = { 1a 33 [2] 3e 3d [2] 15 11 [2] 3b 33 [2] 2f 28 [2] 20 32 [2] 3e 2f [2] 3c 2e [2] 27 28 [2] 3b 2f [2] 27 00 }

  condition:
    any of them
}