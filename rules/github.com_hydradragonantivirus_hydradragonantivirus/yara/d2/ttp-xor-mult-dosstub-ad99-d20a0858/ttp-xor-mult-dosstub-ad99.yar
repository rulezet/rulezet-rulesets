rule TTP_XOR_MULT_DOSStub_ad99 {
  strings:
    $key_ad99 = { f9 f1 [2] 8d e9 [2] ca eb [2] 8d fa [2] c3 f6 [2] cf fc [2] d8 f7 [2] c3 b9 [2] fe }

  condition:
    any of them
}