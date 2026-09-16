rule TTP_XOR_QUAD_CurrentVersionRun_dfdb {
  strings:
    $key_dfdb = { 8c b4 [2] a8 ba [2] 83 96 [2] ad b4 [2] b9 af [2] b6 b5 [2] a8 a8 [2] aa a9 [2] b1 af [2] ad a8 [2] b1 87 }

  condition:
    any of them
}