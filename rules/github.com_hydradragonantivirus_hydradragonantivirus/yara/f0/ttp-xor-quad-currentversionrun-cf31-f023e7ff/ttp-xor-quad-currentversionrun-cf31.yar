rule TTP_XOR_QUAD_CurrentVersionRun_cf31 {
  strings:
    $key_cf31 = { 9c 5e [2] b8 50 [2] 93 7c [2] bd 5e [2] a9 45 [2] a6 5f [2] b8 42 [2] ba 43 [2] a1 45 [2] bd 42 [2] a1 6d }

  condition:
    any of them
}