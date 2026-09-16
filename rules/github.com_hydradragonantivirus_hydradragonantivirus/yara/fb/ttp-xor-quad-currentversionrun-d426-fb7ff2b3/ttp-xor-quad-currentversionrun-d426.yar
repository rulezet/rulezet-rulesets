rule TTP_XOR_QUAD_CurrentVersionRun_d426 {
  strings:
    $key_d426 = { 87 49 [2] a3 47 [2] 88 6b [2] a6 49 [2] b2 52 [2] bd 48 [2] a3 55 [2] a1 54 [2] ba 52 [2] a6 55 [2] ba 7a }

  condition:
    any of them
}