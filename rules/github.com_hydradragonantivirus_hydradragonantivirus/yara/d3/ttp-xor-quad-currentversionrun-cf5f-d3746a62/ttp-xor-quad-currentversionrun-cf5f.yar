rule TTP_XOR_QUAD_CurrentVersionRun_cf5f {
  strings:
    $key_cf5f = { 9c 30 [2] b8 3e [2] 93 12 [2] bd 30 [2] a9 2b [2] a6 31 [2] b8 2c [2] ba 2d [2] a1 2b [2] bd 2c [2] a1 03 }

  condition:
    any of them
}