rule TTP_XOR_QUAD_CurrentVersionRun_acc2 {
  strings:
    $key_acc2 = { ff ad [2] db a3 [2] f0 8f [2] de ad [2] ca b6 [2] c5 ac [2] db b1 [2] d9 b0 [2] c2 b6 [2] de b1 [2] c2 9e }

  condition:
    any of them
}