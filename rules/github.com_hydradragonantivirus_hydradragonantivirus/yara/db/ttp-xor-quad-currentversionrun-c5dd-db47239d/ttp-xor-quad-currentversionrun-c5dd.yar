rule TTP_XOR_QUAD_CurrentVersionRun_c5dd {
  strings:
    $key_c5dd = { 96 b2 [2] b2 bc [2] 99 90 [2] b7 b2 [2] a3 a9 [2] ac b3 [2] b2 ae [2] b0 af [2] ab a9 [2] b7 ae [2] ab 81 }

  condition:
    any of them
}