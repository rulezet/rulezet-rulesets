rule TTP_XOR_QUAD_CurrentVersionRun_acc1 {
  strings:
    $key_acc1 = { ff ae [2] db a0 [2] f0 8c [2] de ae [2] ca b5 [2] c5 af [2] db b2 [2] d9 b3 [2] c2 b5 [2] de b2 [2] c2 9d }

  condition:
    any of them
}