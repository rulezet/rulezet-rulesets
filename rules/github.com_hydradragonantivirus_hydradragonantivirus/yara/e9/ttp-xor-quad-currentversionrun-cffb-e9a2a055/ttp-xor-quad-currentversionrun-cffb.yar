rule TTP_XOR_QUAD_CurrentVersionRun_cffb {
  strings:
    $key_cffb = { 9c 94 [2] b8 9a [2] 93 b6 [2] bd 94 [2] a9 8f [2] a6 95 [2] b8 88 [2] ba 89 [2] a1 8f [2] bd 88 [2] a1 a7 }

  condition:
    any of them
}