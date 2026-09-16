rule TTP_XOR_MULT_DOSStub_a892 {
  strings:
    $key_a892 = { fc fa [2] 88 e2 [2] cf e0 [2] 88 f1 [2] c6 fd [2] ca f7 [2] dd fc [2] c6 b2 [2] fb }

  condition:
    any of them
}