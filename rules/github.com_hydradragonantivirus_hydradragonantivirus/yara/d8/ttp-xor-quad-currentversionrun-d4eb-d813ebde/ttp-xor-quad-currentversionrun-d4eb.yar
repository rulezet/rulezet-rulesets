rule TTP_XOR_QUAD_CurrentVersionRun_d4eb {
  strings:
    $key_d4eb = { 87 84 [2] a3 8a [2] 88 a6 [2] a6 84 [2] b2 9f [2] bd 85 [2] a3 98 [2] a1 99 [2] ba 9f [2] a6 98 [2] ba b7 }

  condition:
    any of them
}