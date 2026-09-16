rule TTP_XOR_QUAD_CurrentVersionRun_dbd2 {
  strings:
    $key_dbd2 = { 88 bd [2] ac b3 [2] 87 9f [2] a9 bd [2] bd a6 [2] b2 bc [2] ac a1 [2] ae a0 [2] b5 a6 [2] a9 a1 [2] b5 8e }

  condition:
    any of them
}