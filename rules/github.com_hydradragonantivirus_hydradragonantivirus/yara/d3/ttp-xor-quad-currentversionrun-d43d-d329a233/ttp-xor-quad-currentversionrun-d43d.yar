rule TTP_XOR_QUAD_CurrentVersionRun_d43d {
  strings:
    $key_d43d = { 87 52 [2] a3 5c [2] 88 70 [2] a6 52 [2] b2 49 [2] bd 53 [2] a3 4e [2] a1 4f [2] ba 49 [2] a6 4e [2] ba 61 }

  condition:
    any of them
}