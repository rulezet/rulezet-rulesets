rule TTP_XOR_QUAD_CurrentVersionRun_90c4 {
  strings:
    $key_90c4 = { c3 ab [2] e7 a5 [2] cc 89 [2] e2 ab [2] f6 b0 [2] f9 aa [2] e7 b7 [2] e5 b6 [2] fe b0 [2] e2 b7 [2] fe 98 }

  condition:
    any of them
}