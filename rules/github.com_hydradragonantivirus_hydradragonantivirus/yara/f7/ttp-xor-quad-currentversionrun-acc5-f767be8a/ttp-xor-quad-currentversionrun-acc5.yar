rule TTP_XOR_QUAD_CurrentVersionRun_acc5 {
  strings:
    $key_acc5 = { ff aa [2] db a4 [2] f0 88 [2] de aa [2] ca b1 [2] c5 ab [2] db b6 [2] d9 b7 [2] c2 b1 [2] de b6 [2] c2 99 }

  condition:
    any of them
}