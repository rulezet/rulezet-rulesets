rule TTP_XOR_QUAD_CurrentVersionRun_dccc {
  strings:
    $key_dccc = { 8f a3 [2] ab ad [2] 80 81 [2] ae a3 [2] ba b8 [2] b5 a2 [2] ab bf [2] a9 be [2] b2 b8 [2] ae bf [2] b2 90 }

  condition:
    any of them
}