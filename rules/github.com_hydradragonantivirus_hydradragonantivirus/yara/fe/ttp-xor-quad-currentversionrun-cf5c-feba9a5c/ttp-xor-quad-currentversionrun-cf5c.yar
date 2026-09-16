rule TTP_XOR_QUAD_CurrentVersionRun_cf5c {
  strings:
    $key_cf5c = { 9c 33 [2] b8 3d [2] 93 11 [2] bd 33 [2] a9 28 [2] a6 32 [2] b8 2f [2] ba 2e [2] a1 28 [2] bd 2f [2] a1 00 }

  condition:
    any of them
}