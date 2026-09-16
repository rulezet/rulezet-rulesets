rule TTP_XOR_QUAD_CurrentVersionRun_d9c0 {
  strings:
    $key_d9c0 = { 8a af [2] ae a1 [2] 85 8d [2] ab af [2] bf b4 [2] b0 ae [2] ae b3 [2] ac b2 [2] b7 b4 [2] ab b3 [2] b7 9c }

  condition:
    any of them
}