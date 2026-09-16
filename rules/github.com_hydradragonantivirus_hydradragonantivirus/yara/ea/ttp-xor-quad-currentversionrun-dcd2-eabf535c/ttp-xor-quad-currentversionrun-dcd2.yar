rule TTP_XOR_QUAD_CurrentVersionRun_dcd2 {
  strings:
    $key_dcd2 = { 8f bd [2] ab b3 [2] 80 9f [2] ae bd [2] ba a6 [2] b5 bc [2] ab a1 [2] a9 a0 [2] b2 a6 [2] ae a1 [2] b2 8e }

  condition:
    any of them
}