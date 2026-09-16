rule TTP_XOR_QUAD_CurrentVersionRun_d4e0 {
  strings:
    $key_d4e0 = { 87 8f [2] a3 81 [2] 88 ad [2] a6 8f [2] b2 94 [2] bd 8e [2] a3 93 [2] a1 92 [2] ba 94 [2] a6 93 [2] ba bc }

  condition:
    any of them
}