rule TTP_XOR_QUAD_CurrentVersionRun_cf2a {
  strings:
    $key_cf2a = { 9c 45 [2] b8 4b [2] 93 67 [2] bd 45 [2] a9 5e [2] a6 44 [2] b8 59 [2] ba 58 [2] a1 5e [2] bd 59 [2] a1 76 }

  condition:
    any of them
}