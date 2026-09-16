rule TTP_XOR_QUAD_CurrentVersionRun_d353 {
  strings:
    $key_d353 = { 80 3c [2] a4 32 [2] 8f 1e [2] a1 3c [2] b5 27 [2] ba 3d [2] a4 20 [2] a6 21 [2] bd 27 [2] a1 20 [2] bd 0f }

  condition:
    any of them
}