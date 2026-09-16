rule TTP_XOR_QUAD_CurrentVersionRun_d346 {
  strings:
    $key_d346 = { 80 29 [2] a4 27 [2] 8f 0b [2] a1 29 [2] b5 32 [2] ba 28 [2] a4 35 [2] a6 34 [2] bd 32 [2] a1 35 [2] bd 1a }

  condition:
    any of them
}