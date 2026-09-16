rule TTP_XOR_QUAD_CurrentVersionRun_dcce {
  strings:
    $key_dcce = { 8f a1 [2] ab af [2] 80 83 [2] ae a1 [2] ba ba [2] b5 a0 [2] ab bd [2] a9 bc [2] b2 ba [2] ae bd [2] b2 92 }

  condition:
    any of them
}