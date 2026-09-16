rule TTP_XOR_QUAD_CurrentVersionRun_dedd {
  strings:
    $key_dedd = { 8d b2 [2] a9 bc [2] 82 90 [2] ac b2 [2] b8 a9 [2] b7 b3 [2] a9 ae [2] ab af [2] b0 a9 [2] ac ae [2] b0 81 }

  condition:
    any of them
}