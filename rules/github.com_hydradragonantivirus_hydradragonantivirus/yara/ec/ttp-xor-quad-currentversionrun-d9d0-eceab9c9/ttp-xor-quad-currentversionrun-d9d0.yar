rule TTP_XOR_QUAD_CurrentVersionRun_d9d0 {
  strings:
    $key_d9d0 = { 8a bf [2] ae b1 [2] 85 9d [2] ab bf [2] bf a4 [2] b0 be [2] ae a3 [2] ac a2 [2] b7 a4 [2] ab a3 [2] b7 8c }

  condition:
    any of them
}