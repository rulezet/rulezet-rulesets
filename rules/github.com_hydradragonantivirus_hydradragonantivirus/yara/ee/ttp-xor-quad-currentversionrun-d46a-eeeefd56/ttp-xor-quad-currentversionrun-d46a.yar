rule TTP_XOR_QUAD_CurrentVersionRun_d46a {
  strings:
    $key_d46a = { 87 05 [2] a3 0b [2] 88 27 [2] a6 05 [2] b2 1e [2] bd 04 [2] a3 19 [2] a1 18 [2] ba 1e [2] a6 19 [2] ba 36 }

  condition:
    any of them
}