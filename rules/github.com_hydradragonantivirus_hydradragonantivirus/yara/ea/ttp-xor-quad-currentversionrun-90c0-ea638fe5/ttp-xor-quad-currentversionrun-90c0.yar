rule TTP_XOR_QUAD_CurrentVersionRun_90c0 {
  strings:
    $key_90c0 = { c3 af [2] e7 a1 [2] cc 8d [2] e2 af [2] f6 b4 [2] f9 ae [2] e7 b3 [2] e5 b2 [2] fe b4 [2] e2 b3 [2] fe 9c }

  condition:
    any of them
}