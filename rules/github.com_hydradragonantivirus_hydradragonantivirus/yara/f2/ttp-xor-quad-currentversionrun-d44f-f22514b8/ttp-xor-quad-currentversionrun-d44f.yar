rule TTP_XOR_QUAD_CurrentVersionRun_d44f {
  strings:
    $key_d44f = { 87 20 [2] a3 2e [2] 88 02 [2] a6 20 [2] b2 3b [2] bd 21 [2] a3 3c [2] a1 3d [2] ba 3b [2] a6 3c [2] ba 13 }

  condition:
    any of them
}