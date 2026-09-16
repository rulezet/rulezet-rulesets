rule TTP_XOR_QUAD_CurrentVersionRun_acc6 {
  strings:
    $key_acc6 = { ff a9 [2] db a7 [2] f0 8b [2] de a9 [2] ca b2 [2] c5 a8 [2] db b5 [2] d9 b4 [2] c2 b2 [2] de b5 [2] c2 9a }

  condition:
    any of them
}