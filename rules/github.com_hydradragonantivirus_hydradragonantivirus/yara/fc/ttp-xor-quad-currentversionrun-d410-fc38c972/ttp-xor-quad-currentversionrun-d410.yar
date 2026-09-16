rule TTP_XOR_QUAD_CurrentVersionRun_d410 {
  strings:
    $key_d410 = { 87 7f [2] a3 71 [2] 88 5d [2] a6 7f [2] b2 64 [2] bd 7e [2] a3 63 [2] a1 62 [2] ba 64 [2] a6 63 [2] ba 4c }

  condition:
    any of them
}